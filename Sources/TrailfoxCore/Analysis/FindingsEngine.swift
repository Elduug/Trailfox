import Foundation

public struct FindingsThresholds: Codable, Sendable {
    public var lowDiskBytes: Int64 = 25_000_000_000
    public var criticalDiskBytes: Int64 = 10_000_000_000
    public var longUptimeDays: Int = 14
    public var repeatedCrashCount: Int = 3
    public init() {}
}

public protocol FindingRule: Sendable {
    func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding]
}

public struct FindingsEngine: Sendable {
    public var thresholds: FindingsThresholds
    private let rules: [any FindingRule]
    public init(thresholds: FindingsThresholds = .init(), rules: [any FindingRule] = [StorageRule(), DNSCorrelationRule(), UptimeRule(), TunnelRule(), CrashRule(), SecurityRule(), CollectorHealthRule()]) {
        self.thresholds = thresholds; self.rules = rules
    }
    public func evaluate(_ snapshot: DiagnosticSnapshot) -> [Finding] {
        rules.flatMap { $0.evaluate(snapshot, thresholds: thresholds) }.sorted { $0.severity == $1.severity ? $0.title < $1.title : $0.severity > $1.severity }
    }
}

public struct StorageRule: FindingRule {
    public init() {}
    public func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding] {
        guard let metric = snapshot.result(.storage)?.metrics.first(where: { $0.id == "freeBytes" }), let raw = metric.detail, let bytes = Int64(raw), bytes < thresholds.lowDiskBytes else { return [] }
        let severity: Severity = bytes < thresholds.criticalDiskBytes ? .critical : .warning
        return [Finding(title: "Available storage is low", category: .storage, severity: severity, confidence: .strong,
            explanation: "Your Mac is running low on free storage. macOS and applications need working space for updates, caches, and virtual memory.",
            observedEvidence: "Only \(metric.value) is available on the startup volume.", likelyImpact: "Updates may fail and the Mac may become less responsive.",
            recommendation: "Review large personal files and application data. Trailfox will not delete anything automatically.", technicalDetails: "Threshold: \(Parse.humanBytes(thresholds.lowDiskBytes)); observed: \(bytes) bytes")]
    }
}

public struct DNSCorrelationRule: FindingRule {
    public init() {}
    public func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding] {
        guard snapshot.result(.dns)?.metric("dnsWorks") == "Failed" else { return [] }
        let ipWorks = snapshot.result(.network)?.metric("ipReachable") == "Reachable"
        return [Finding(title: ipWorks ? "DNS resolution is failing" : "Name resolution could not be verified", category: .dns, severity: ipWorks ? .warning : .review, confidence: ipWorks ? .strong : .moderate,
            explanation: ipWorks ? "Your Mac can reach the internet by IP address, but domain-name lookups failed. This points to DNS rather than a complete connection loss." : "Domain-name lookups failed while general connectivity was also unavailable, so DNS may not be the only issue.",
            observedEvidence: "Two external name lookups failed\(ipWorks ? " while the public IP reachability test succeeded" : "").", likelyImpact: "Websites and cloud applications can appear offline or connect intermittently.",
            recommendation: "Review configured resolvers and active VPN, DNS proxy, or content-filter software. Re-test before changing settings.")]
    }
}

public struct UptimeRule: FindingRule {
    public init() {}
    public func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding] {
        guard let value = snapshot.result(.system)?.metric("uptimeDays"), let days = Int(value.split(separator: " ").first ?? "0"), days >= thresholds.longUptimeDays else { return [] }
        return [Finding(title: "The Mac has not restarted recently", category: .system, severity: .review, confidence: .strong, explanation: "The Mac has been running continuously for \(days) days. Long uptime is not inherently a problem, but a restart can complete updates and clear transient service failures.", observedEvidence: "Uptime is \(days) days.", likelyImpact: "Pending updates or stale background services may persist.", recommendation: "When convenient, save work and restart normally, especially if symptoms began after an update.")]
    }
}

public struct TunnelRule: FindingRule {
    public init() {}
    public func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding] {
        guard let text = snapshot.result(.vpn)?.metric("tunnelCount"), let count = Int(text), count > 1 else { return [] }
        return [Finding(title: "Multiple network tunnels are active", category: .vpn, severity: .review, confidence: .strong, explanation: "Multiple tunnel interfaces may be normal, but they can make routing and DNS troubleshooting more complex.", observedEvidence: "\(count) active utun interfaces were detected.", likelyImpact: "Traffic or DNS may follow a route that is not obvious.", recommendation: "Compare the active tunnels with the VPN, security, and networking tools you expect. Do not disable them solely because Trailfox detected them.")]
    }
}

public struct CrashRule: FindingRule {
    public init() {}
    public func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding] {
        let logs = snapshot.result(.logs)
        var output: [Finding] = []
        if let panics = Int(logs?.metric("panicCount") ?? "0"), panics > 0 {
            output.append(Finding(title: "Recent panic reports were found", category: .logs, severity: .warning, confidence: .moderate, explanation: "Trailfox found diagnostic report names that appear to be kernel panic reports from the last 30 days.", observedEvidence: "\(panics) possible panic report(s).", likelyImpact: "Kernel panics cause unexpected restarts and may indicate software, peripheral, or hardware instability.", recommendation: "Inspect the newest panic report and note any recently attached docks, peripherals, or installed system software. A filename match does not prove a cause."))
        }
        if let crashes = Int(logs?.metric("crashReportCount") ?? "0"), crashes >= thresholds.repeatedCrashCount {
            output.append(Finding(title: "Multiple recent diagnostic reports", category: .logs, severity: .review, confidence: .moderate, explanation: "Several crash or diagnostic reports were created recently. Some may be unrelated, so the grouped technical evidence is the useful next step.", observedEvidence: "\(crashes) reports in the last 30 days.", likelyImpact: "One or more applications or services may be unstable.", recommendation: "Look for the same process appearing repeatedly, then confirm that application and macOS are current."))
        }
        return output
    }
}

public struct SecurityRule: FindingRule {
    public init() {}
    public func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding] {
        guard let security = snapshot.result(.security) else { return [] }
        let off = security.metrics.filter { ["fileVault", "firewall", "gatekeeper", "sip"].contains($0.id) && $0.value == "Off or unavailable" }
        guard !off.isEmpty else { return [] }
        return [Finding(title: "Some security controls are off or unavailable", category: .security, severity: .informational, confidence: .weak, explanation: "Trailfox could not confirm every common macOS security control. An unavailable result is not the same as disabled.", observedEvidence: off.map(\.label).joined(separator: ", "), likelyImpact: "Security posture cannot be fully summarized from the current scan.", recommendation: "Confirm these controls in System Settings or with your organization before making changes.")]
    }
}

public struct CollectorHealthRule: FindingRule {
    public init() {}
    public func evaluate(_ snapshot: DiagnosticSnapshot, thresholds: FindingsThresholds) -> [Finding] {
        let failures = snapshot.results.flatMap { result in result.errors.map { "\(result.category.title): \($0.message)" } }
        guard !failures.isEmpty else { return [] }
        return [Finding(title: "Some diagnostic data was unavailable", category: .overview, severity: .informational, confidence: .strong, explanation: "Trailfox completed the scan, but macOS restrictions or command failures prevented a few checks. Other collectors continued normally.", observedEvidence: failures.prefix(5).joined(separator: "\n"), likelyImpact: "The report may be incomplete in the named areas.", recommendation: "Review the affected section for a permission hint. Grant additional access only if the missing detail is useful.")]
    }
}
