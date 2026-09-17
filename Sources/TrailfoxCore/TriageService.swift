import Foundation

public struct TriageService: Sendable {
    public let collectors: [any DiagnosticCollector]
    public let findingsEngine: FindingsEngine
    public init(collectors: [any DiagnosticCollector] = TriageService.standardCollectors, findingsEngine: FindingsEngine = .init()) {
        self.collectors = collectors; self.findingsEngine = findingsEngine
    }
    public static var standardCollectors: [any DiagnosticCollector] {
        [SystemCollector(), PerformanceCollector(), StorageCollector(), NetworkCollector(), DNSCollector(), WiFiCollector(), VPNCollector(), ProcessCollector(), BackgroundItemsCollector(), LogCollector(), CrashCollector(), SecurityCollector(), BatteryCollector(), HardwareCollector(), DisplayCollector(), UpdateCollector()]
    }
    public func run(progress: @escaping @Sendable (String, Double) async -> Void = { _, _ in }) async -> DiagnosticSnapshot {
        let started = Date(); var gathered: [DiagnosticResult] = []; var completed = 0
        await progress("Starting local diagnostics…", 0)
        await withTaskGroup(of: DiagnosticResult.self) { group in
            for collector in collectors { group.addTask { await collector.collect() } }
            for await result in group {
                gathered.append(result); completed += 1
                await progress("Collected \(result.category.title)", Double(completed) / Double(collectors.count))
            }
        }
        let merged = merge(gathered).sorted { $0.category.title < $1.category.title }
        var snapshot = DiagnosticSnapshot(startedAt: started, completedAt: Date(), results: merged)
        snapshot.findings = findingsEngine.evaluate(snapshot)
        await progress("Triage complete", 1)
        return snapshot
    }
    private func merge(_ results: [DiagnosticResult]) -> [DiagnosticResult] {
        Dictionary(grouping: results, by: \.category).map { category, parts in
            DiagnosticResult(category: category, summary: parts.map(\.summary).joined(separator: " · "), metrics: parts.flatMap(\.metrics), evidence: parts.flatMap(\.evidence), errors: parts.flatMap(\.errors), collectedAt: parts.map(\.collectedAt).max() ?? Date())
        }
    }
}
