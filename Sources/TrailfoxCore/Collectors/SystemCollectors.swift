import Foundation

public struct SystemCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.system
    public let name = "System"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let profile = runner.run("/usr/sbin/system_profiler", ["SPHardwareDataType", "SPSoftwareDataType", "-detailLevel", "mini"], timeout: 15)
            async let uptime = runner.run("/usr/bin/uptime", timeout: 3)
            async let translated = runner.run("/usr/sbin/sysctl", ["-n", "sysctl.proc_translated"], timeout: 2)
            let (p, u, t) = try await (profile, uptime, translated)
            let text = p.stdout
            let model = Parse.firstValue(text, after: "Model Name") ?? "Mac"
            let modelID = Parse.firstValue(text, after: "Model Identifier") ?? "Unavailable"
            let chip = Parse.firstValue(text, after: "Chip") ?? Parse.firstValue(text, after: "Processor Name") ?? "Unavailable"
            let memory = Parse.firstValue(text, after: "Memory") ?? "Unavailable"
            let version = Parse.firstValue(text, after: "System Version") ?? ProcessInfo.processInfo.operatingSystemVersionString
            let boot = ProcessInfo.processInfo.systemUptime
            let days = Int(boot / 86_400)
            let architecture = chip.localizedCaseInsensitiveContains("Apple") ? "Apple Silicon" : "Intel"
            let metrics = [
                Metric(id: "model", label: "Model", value: model), Metric(id: "modelIdentifier", label: "Model Identifier", value: modelID),
                Metric(id: "osVersion", label: "macOS", value: version), Metric(id: "architecture", label: "Architecture", value: architecture),
                Metric(id: "cpu", label: "Processor", value: chip), Metric(id: "cores", label: "CPU Cores", value: "\(ProcessInfo.processInfo.processorCount)"),
                Metric(id: "memory", label: "Memory", value: memory), Metric(id: "hostname", label: "Hostname", value: Host.current().localizedName ?? "Unavailable", sensitive: true),
                Metric(id: "username", label: "Current User", value: NSUserName(), sensitive: true), Metric(id: "uptimeDays", label: "Uptime", value: "\(days) days", detail: u.stdout),
                Metric(id: "rosetta", label: "Running via Rosetta", value: t.stdout == "1" ? "Yes" : "No")
            ]
            return DiagnosticResult(category: category, summary: "\(model) · \(version)", metrics: metrics,
                evidence: [Evidence(category: category, title: "System profile", summary: "Hardware and software identity collected locally.", technicalDetail: text, source: "system_profiler")])
        } catch {
            return DiagnosticResult(category: category, summary: "System details partially unavailable", metrics: [Metric(id: "osVersion", label: "macOS", value: ProcessInfo.processInfo.operatingSystemVersionString)], errors: [CollectorError(error.localizedDescription)])
        }
    }
}

public struct PerformanceCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.performance
    public let name = "Performance"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let top = runner.run("/usr/bin/top", ["-l", "1", "-n", "0"], timeout: 8)
            async let vm = runner.run("/usr/bin/vm_stat", timeout: 5)
            async let swap = runner.run("/usr/sbin/sysctl", ["vm.swapusage"], timeout: 3)
            async let processes = runner.run("/bin/ps", ["-axo", "pid,pcpu,pmem,comm", "-r"], timeout: 5)
            let (a, b, c, d) = try await (top, vm, swap, processes)
            let cpu = a.stdout.split(separator: "\n").first { $0.contains("CPU usage") }.map(String.init) ?? "Unavailable"
            let phys = a.stdout.split(separator: "\n").first { $0.contains("PhysMem") }.map(String.init) ?? "Unavailable"
            let load = a.stdout.split(separator: "\n").first { $0.contains("Load Avg") }.map(String.init) ?? "Unavailable"
            let count = a.stdout.split(separator: "\n").first { $0.contains("Processes:") }.map(String.init) ?? "Unavailable"
            let swapValue = c.stdout.replacingOccurrences(of: "vm.swapusage: ", with: "")
            let topProcesses = d.stdout.split(separator: "\n").prefix(9).joined(separator: "\n")
            return DiagnosticResult(category: category, summary: phys,
                metrics: [Metric(id: "cpu", label: "CPU", value: cpu), Metric(id: "memoryPressure", label: "Memory", value: phys), Metric(id: "swap", label: "Swap", value: swapValue), Metric(id: "load", label: "Load", value: load), Metric(id: "processCount", label: "Processes", value: count)],
                evidence: [Evidence(category: category, title: "Virtual memory statistics", summary: "Memory counters and leading processes were sampled.", technicalDetail: b.stdout + "\n\nTop processes:\n" + topProcesses, source: "top, vm_stat, ps")])
        } catch { return DiagnosticResult(category: category, summary: "Performance sample unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct StorageCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.storage
    public let name = "Storage"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let df = runner.run("/bin/df", ["-k", "/"], timeout: 5)
            async let disks = runner.run("/usr/sbin/diskutil", ["list"], timeout: 8)
            async let tm = runner.run("/usr/bin/tmutil", ["status"], timeout: 5)
            let (d, disk, timeMachine) = try await (df, disks, tm)
            let fields = d.stdout.split(separator: "\n").last?.split(whereSeparator: { $0 == " " || $0 == "\t" }) ?? []
            let totalKB = fields.count > 1 ? Int64(fields[1]) ?? 0 : 0
            let availableKB = fields.count > 3 ? Int64(fields[3]) ?? 0 : 0
            let used = fields.count > 4 ? String(fields[4]) : "Unavailable"
            let freeBytes = availableKB * 1024
            return DiagnosticResult(category: category, summary: "\(Parse.humanBytes(freeBytes)) free",
                metrics: [Metric(id: "capacityBytes", label: "Capacity", value: Parse.humanBytes(totalKB * 1024), detail: "\(totalKB * 1024)"), Metric(id: "freeBytes", label: "Free Space", value: Parse.humanBytes(freeBytes), detail: "\(freeBytes)"), Metric(id: "usedPercent", label: "Used", value: used), Metric(id: "timeMachine", label: "Time Machine", value: timeMachine.succeeded ? (Parse.firstValue(timeMachine.stdout, after: "Running") ?? "Configured") : "Unavailable")],
                evidence: [Evidence(category: category, title: "Mounted storage", summary: "Root capacity and attached disks were inspected.", technicalDetail: d.stdout + "\n\n" + disk.stdout, source: "df, diskutil, tmutil")])
        } catch { return DiagnosticResult(category: category, summary: "Storage details unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}
