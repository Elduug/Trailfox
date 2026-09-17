import Foundation

public struct ReportGenerator: Sendable {
    public init() {}
    public func summary(for snapshot: DiagnosticSnapshot) -> String {
        let attention = snapshot.findings.filter { $0.severity >= .review }.count
        var lines = ["TRAILFOX DIAGNOSTIC SUMMARY", "Generated: \(snapshot.completedAt.formatted(date: .abbreviated, time: .shortened))", "", "SUMMARY", "\(attention) item\(attention == 1 ? "" : "s") require attention"]
        for finding in snapshot.findings.prefix(8) { lines += ["", "\(finding.severity.label.uppercased()) — \(finding.title)", finding.explanation, "Suggested investigation: \(finding.recommendation)"] }
        return lines.joined(separator: "\n")
    }
    public func fullReport(for snapshot: DiagnosticSnapshot) -> String {
        var lines = ["TRAILFOX DIAGNOSTIC REPORT", "Generated: \(snapshot.completedAt.formatted(date: .abbreviated, time: .standard))", "Scan ID: \(snapshot.id.uuidString)", "", "SUMMARY", "\(snapshot.findings.filter { $0.severity >= .review }.count) items require attention"]
        for result in snapshot.results.sorted(by: { $0.category.title < $1.category.title }) {
            lines += ["", result.category.title.uppercased(), result.summary]
            lines += result.metrics.map { "\($0.label): \($0.value)" }
            for error in result.errors { lines.append("Unavailable: \(error.message)\(error.permissionHint.map { " — \($0)" } ?? "")") }
        }
        lines += ["", "FINDINGS"]
        if snapshot.findings.isEmpty { lines.append("No rule-based findings require attention.") }
        for item in snapshot.findings {
            lines += ["", "\(item.severity.label.uppercased()) — \(item.title)", "Confidence: \(item.confidence.rawValue)", item.explanation, "Observed: \(item.observedEvidence)", "Likely impact: \(item.likelyImpact)", "Suggested investigation: \(item.recommendation)"]
            if !item.technicalDetails.isEmpty { lines.append("Technical details: \(item.technicalDetails)") }
        }
        lines += ["", "TECHNICAL EVIDENCE"]
        for result in snapshot.results { for evidence in result.evidence { lines += ["", "[\(result.category.title)] \(evidence.title)", "Source: \(evidence.source)", evidence.technicalDetail] } }
        lines += ["", "Trailfox is read-only. No diagnostic data was transmitted."]
        return lines.joined(separator: "\n")
    }
}

public struct SanitizerOptions: Codable, Sendable {
    public var redactUsername = true, redactHostname = true, redactSerialNumber = true, redactMACAddresses = true
    public var redactIPAddresses = true, redactSSID = true, redactEmailAddresses = true
    public init() {}
}

public struct ReportSanitizer: Sendable {
    public var options: SanitizerOptions
    public init(options: SanitizerOptions = .init()) { self.options = options }
    public func sanitize(_ report: String, snapshot: DiagnosticSnapshot? = nil) -> String {
        var text = report
        if options.redactUsername {
            let user = NSUserName(); if !user.isEmpty { text = text.replacingOccurrences(of: "/Users/\(user)/", with: "/Users/<user>/").replacingOccurrences(of: user, with: "<user>") }
        }
        if options.redactHostname, let host = snapshot?.result(.system)?.metric("hostname"), !host.isEmpty { text = text.replacingOccurrences(of: host, with: "<hostname>") }
        if options.redactSerialNumber { text = regex(text, #"(?i)(serial(?: number)?\s*:\s*)[A-Z0-9-]{6,}"#, "$1<serial>") }
        if options.redactMACAddresses { text = regex(text, #"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b"#, "<mac-address>") }
        if options.redactEmailAddresses { text = regex(text, #"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"#, "<email>", options: [.caseInsensitive]) }
        if options.redactIPAddresses {
            text = regex(text, #"\b(?:\d{1,3}\.){3}\d{1,3}\b"#, "<ip-address>")
            text = regex(text, #"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"#, "<ipv6-address>")
        }
        if options.redactSSID { text = regex(text, #"(?i)(ssid\s*:\s*)[^\n]+"#, "$1<ssid>") }
        return text
    }
    private func regex(_ text: String, _ pattern: String, _ replacement: String, options: NSRegularExpression.Options = []) -> String {
        guard let expression = try? NSRegularExpression(pattern: pattern, options: options) else { return text }
        return expression.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: replacement)
    }
}
