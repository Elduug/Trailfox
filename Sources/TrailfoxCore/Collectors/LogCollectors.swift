import Foundation

public struct LogCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.logs
    public let name = "Logs & Errors"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        let predicate = "eventMessage CONTAINS[c] 'DNS' OR eventMessage CONTAINS[c] 'disconnect' OR eventMessage CONTAINS[c] 'disk full' OR eventMessage CONTAINS[c] 'failed'"
        do {
            let result = try await runner.run("/usr/bin/log", ["show", "--last", "2h", "--style", "compact", "--predicate", predicate], timeout: 14)
            let lines = result.stdout.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
            let groups = LogGrouper.group(lines: lines)
            let details = groups.prefix(30).map { "[\($0.count)x] \($0.sample)" }.joined(separator: "\n")
            return DiagnosticResult(category: category, summary: "\(groups.count) grouped high-signal log patterns",
                metrics: [Metric(id: "logEventCount", label: "Matching Events", value: "\(lines.count)"), Metric(id: "logGroupCount", label: "Grouped Patterns", value: "\(groups.count)"), Metric(id: "logWindow", label: "Window", value: "Last 2 hours")],
                evidence: [Evidence(category: category, title: "Grouped system events", summary: "Potentially relevant events were filtered and duplicates grouped; this is not a raw log dump.", technicalDetail: details, source: "macOS Unified Log")],
                errors: result.timedOut ? [CollectorError("Log query reached its time limit; partial evidence is shown.")] : [])
        } catch { return DiagnosticResult(category: category, summary: "Unified Log unavailable", errors: [CollectorError(error.localizedDescription, permissionHint: "Some log content requires Full Disk Access; Trailfox continues without it.")]) }
    }
}

public struct CrashCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.logs
    public let name = "Crashes & Panics"
    public init() {}
    public func collect() async -> DiagnosticResult {
        await Task.detached(priority: .utility) {
            let fm = FileManager.default
            let dirs = [fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/DiagnosticReports"), URL(fileURLWithPath: "/Library/Logs/DiagnosticReports")]
            let cutoff = Date().addingTimeInterval(-30 * 86_400)
            var names: [String] = []; var panics = 0
            for dir in dirs {
                let files = (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles])) ?? []
                for file in files {
                    let date = (try? file.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                    guard date >= cutoff else { continue }
                    names.append(file.lastPathComponent)
                    if file.lastPathComponent.localizedCaseInsensitiveContains("panic") { panics += 1 }
                }
            }
            let grouped = Dictionary(grouping: names) { $0.split(separator: "_").first.map(String.init) ?? $0 }.map { ($0.key, $0.value.count) }.sorted { $0.1 > $1.1 }
            let evidence = grouped.prefix(25).map { "\($0.0): \($0.1) report(s)" }.joined(separator: "\n")
            return DiagnosticResult(category: .logs, summary: "\(names.count) recent diagnostic reports", metrics: [Metric(id: "crashReportCount", label: "Crash / Diagnostic Reports", value: "\(names.count)"), Metric(id: "panicCount", label: "Possible Panic Reports", value: "\(panics)")], evidence: [Evidence(category: .logs, title: "Crash and panic report index", summary: "Report names from the last 30 days were grouped by process without copying full crash contents.", technicalDetail: evidence, source: "DiagnosticReports")])
        }.value
    }
}

public struct LogGroup: Equatable, Sendable { public let key: String; public let count: Int; public let sample: String }
public enum LogGrouper {
    public static func normalize(_ line: String) -> String {
        line.lowercased()
            .replacingOccurrences(of: #"\b[0-9a-f]{8,}\b"#, with: "<id>", options: .regularExpression)
            .replacingOccurrences(of: #"\b\d+\b"#, with: "<n>", options: .regularExpression)
            .replacingOccurrences(of: #"^\S+\s+\S+\s+"#, with: "", options: .regularExpression)
    }
    public static func group(lines: [String]) -> [LogGroup] {
        Dictionary(grouping: lines, by: normalize).map { LogGroup(key: $0.key, count: $0.value.count, sample: $0.value[0]) }.sorted { $0.count == $1.count ? $0.key < $1.key : $0.count > $1.count }
    }
}
