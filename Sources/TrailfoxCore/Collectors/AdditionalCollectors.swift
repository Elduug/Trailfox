import Foundation

public struct ProcessCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.processes
    public let name = "Processes"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            let result = try await runner.run("/bin/ps", ["-axo", "pid,ppid,pcpu,pmem,etime,comm", "-r"], timeout: 7)
            let lines = result.stdout.split(separator: "\n")
            let enterprise = ["Webex", "Teams", "OneDrive", "Tailscale", "Cloudflare", "Cisco", "Defender"].filter { name in result.stdout.localizedCaseInsensitiveContains(name) }
            return DiagnosticResult(category: category, summary: "\(max(0, lines.count - 1)) running processes",
                metrics: [Metric(id: "processCount", label: "Process Count", value: "\(max(0, lines.count - 1))"), Metric(id: "recognizedApps", label: "Recognized Support Apps", value: enterprise.isEmpty ? "None detected" : enterprise.joined(separator: ", "))],
                evidence: [Evidence(category: category, title: "Top processes", summary: "Processes are ordered by current CPU use.", technicalDetail: lines.prefix(35).joined(separator: "\n"), source: "ps")])
        } catch { return DiagnosticResult(category: category, summary: "Process list unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct BackgroundItemsCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.background
    public let name = "Background Items"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let launch = runner.run("/bin/launchctl", ["list"], timeout: 8)
            async let bt = runner.run("/usr/sbin/sfltool", ["dumpbtm"], timeout: 10)
            let (a, b) = try await (launch, bt)
            let services = a.stdout.split(separator: "\n")
            let thirdParty = services.filter { !$0.contains("com.apple.") }
            return DiagnosticResult(category: category, summary: "\(services.count) loaded services",
                metrics: [Metric(id: "loadedServices", label: "Loaded Services", value: "\(services.count)"), Metric(id: "thirdPartyServices", label: "Non-Apple Labels", value: "\(thirdParty.count)")],
                evidence: [Evidence(category: category, title: "Loaded and registered background items", summary: "Apple and third-party services remain separated in technical evidence.", technicalDetail: a.stdout + "\n\nBackground task management:\n" + (b.stdout.isEmpty ? b.stderr : b.stdout), source: "launchctl, sfltool")],
                errors: b.succeeded ? [] : [CollectorError("Some background-item metadata is restricted.", permissionHint: "Trailfox continued with the visible launchctl service list.")])
        } catch { return DiagnosticResult(category: category, summary: "Background items partially unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct SecurityCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.security
    public let name = "Security"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let fv = runner.run("/usr/bin/fdesetup", ["status"], timeout: 5)
            async let firewall = runner.run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], timeout: 5)
            async let gatekeeper = runner.run("/usr/sbin/spctl", ["--status"], timeout: 5)
            async let sip = runner.run("/usr/bin/csrutil", ["status"], timeout: 5)
            async let profiles = runner.run("/usr/bin/profiles", ["status", "-type", "enrollment"], timeout: 8)
            let (a, b, c, d, e) = try await (fv, firewall, gatekeeper, sip, profiles)
            func status(_ text: String, enabledWords: [String]) -> String { enabledWords.contains(where: { text.localizedCaseInsensitiveContains($0) }) ? "On" : "Off or unavailable" }
            let metrics = [
                Metric(id: "fileVault", label: "FileVault", value: status(a.stdout, enabledWords: ["FileVault is On"])),
                Metric(id: "firewall", label: "Firewall", value: status(b.stdout, enabledWords: ["enabled", "State = 1"])),
                Metric(id: "gatekeeper", label: "Gatekeeper", value: status(c.stdout, enabledWords: ["assessments enabled"])),
                Metric(id: "sip", label: "System Integrity Protection", value: status(d.stdout, enabledWords: ["enabled"])),
                Metric(id: "mdm", label: "Device Management", value: e.stdout.localizedCaseInsensitiveContains("enrolled") ? e.stdout.replacingOccurrences(of: "\n", with: " · ") : "Not enrolled or unavailable")
            ]
            return DiagnosticResult(category: category, summary: "Security controls reported without active scanning", metrics: metrics,
                evidence: [Evidence(category: category, title: "Security posture", summary: "Trailfox reports status only; this is not an antivirus scan.", technicalDetail: [a.stdout,b.stdout,c.stdout,d.stdout,e.stdout].joined(separator: "\n"), source: "fdesetup, socketfilterfw, spctl, csrutil, profiles")])
        } catch { return DiagnosticResult(category: category, summary: "Security status partially unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct BatteryCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.battery
    public let name = "Battery"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let battery = runner.run("/usr/bin/pmset", ["-g", "batt"], timeout: 5)
            async let detail = runner.run("/usr/sbin/system_profiler", ["SPPowerDataType", "-detailLevel", "mini"], timeout: 10)
            let (a, b) = try await (battery, detail)
            let noBattery = a.stdout.localizedCaseInsensitiveContains("no batteries")
            let condition = Parse.firstValue(b.stdout, after: "Condition") ?? (noBattery ? "Not applicable" : "Unavailable")
            let cycles = Parse.firstValue(b.stdout, after: "Cycle Count") ?? "Unavailable"
            let capacity = Parse.firstValue(b.stdout, after: "Maximum Capacity") ?? "Unavailable"
            return DiagnosticResult(category: category, summary: noBattery ? "No internal battery" : (a.stdout.split(separator: "\n").last.map(String.init) ?? "Battery available"),
                metrics: [Metric(id: "batteryCondition", label: "Condition", value: condition), Metric(id: "cycleCount", label: "Cycle Count", value: cycles), Metric(id: "maximumCapacity", label: "Maximum Capacity", value: capacity)],
                evidence: [Evidence(category: category, title: "Power source", summary: "Battery and charger state were inspected.", technicalDetail: a.stdout + "\n\n" + b.stdout, source: "pmset, system_profiler")])
        } catch { return DiagnosticResult(category: category, summary: "Battery details unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct HardwareCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.hardware
    public let name = "Hardware"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            let value = try await runner.run("/usr/sbin/system_profiler", ["SPUSBDataType", "SPThunderboltDataType", "SPAudioDataType", "SPBluetoothDataType", "-detailLevel", "mini"], timeout: 18)
            let usb = value.stdout.components(separatedBy: "USB").count - 1
            return DiagnosticResult(category: category, summary: "Attached hardware inventoried", metrics: [Metric(id: "hardwareGroups", label: "Hardware data", value: value.stdout.isEmpty ? "Unavailable" : "Available"), Metric(id: "usbMentions", label: "USB Entries", value: "\(max(0, usb))")], evidence: [Evidence(category: category, title: "Attached devices", summary: "USB, Thunderbolt, audio, and Bluetooth information was collected.", technicalDetail: value.stdout, source: "system_profiler")])
        } catch { return DiagnosticResult(category: category, summary: "Hardware inventory unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct DisplayCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.displays
    public let name = "Displays & Input"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            let value = try await runner.run("/usr/sbin/system_profiler", ["SPDisplaysDataType", "SPUSBDataType", "-detailLevel", "mini"], timeout: 12)
            let displayCount = value.stdout.split(separator: "\n").filter { $0.contains("Resolution:") }.count
            return DiagnosticResult(category: category, summary: "\(displayCount) display\(displayCount == 1 ? "" : "s") detected", metrics: [Metric(id: "displayCount", label: "Displays", value: "\(displayCount)"), Metric(id: "inputTest", label: "Interactive Input Test", value: "Planned")], evidence: [Evidence(category: category, title: "Display and input inventory", summary: "Display modes and USB input devices are shown in technical evidence.", technicalDetail: value.stdout, source: "system_profiler")])
        } catch { return DiagnosticResult(category: category, summary: "Display details unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct UpdateCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.updates
    public let name = "Updates"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let history = runner.run("/usr/sbin/system_profiler", ["SPInstallHistoryDataType", "-detailLevel", "mini"], timeout: 15)
            async let prefs = runner.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"], timeout: 4)
            let (h, p) = try await (history, prefs)
            return DiagnosticResult(category: category, summary: "Update history collected", metrics: [Metric(id: "automaticChecks", label: "Automatic Update Checks", value: p.stdout == "1" ? "On" : "Off or unavailable"), Metric(id: "availableUpdates", label: "Available Updates", value: "Not queried during quick triage", detail: "Use Software Update in System Settings for an authoritative check.")], evidence: [Evidence(category: category, title: "Recent installations", summary: "Install history is collected without triggering a slow update scan.", technicalDetail: h.stdout.split(separator: "\n").suffix(120).joined(separator: "\n"), source: "system_profiler, defaults")])
        } catch { return DiagnosticResult(category: category, summary: "Update history unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}
