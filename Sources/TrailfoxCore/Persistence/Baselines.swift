import Foundation

public struct BaselineComparator: Sendable {
    public init() {}
    public func compare(_ old: DiagnosticSnapshot, _ new: DiagnosticSnapshot) -> [BaselineChange] {
        let watched: [DiagnosticCategory: Set<String>] = [
            .system: ["osVersion", "modelIdentifier"], .storage: ["freeBytes"], .network: ["interface", "gateway"],
            .dns: ["dnsServers", "dnsWorks"], .vpn: ["tunnelCount", "tunnels"], .security: ["fileVault", "firewall", "gatekeeper", "sip"],
            .battery: ["batteryCondition", "maximumCapacity"], .background: ["thirdPartyServices"]
        ]
        var changes: [BaselineChange] = []
        for (category, ids) in watched {
            guard let before = old.result(category), let after = new.result(category) else { continue }
            for id in ids {
                guard let a = before.metrics.first(where: { $0.id == id }), let b = after.metrics.first(where: { $0.id == id }), a.value != b.value else { continue }
                if category == .storage, id == "freeBytes", let oldBytes = Int64(a.detail ?? ""), let newBytes = Int64(b.detail ?? ""), abs(oldBytes - newBytes) < 2_000_000_000 { continue }
                let severity: Severity = (category == .dns && id == "dnsWorks" && b.value == "Failed") ? .warning : .review
                changes.append(BaselineChange(category: category, label: b.label, oldValue: a.value, newValue: b.value, significance: severity))
            }
        }
        return changes.sorted { $0.significance == $1.significance ? $0.category.title < $1.category.title : $0.significance > $1.significance }
    }
}

public actor SnapshotStore {
    private let directory: URL
    private let encoder: JSONEncoder
    private let decoder = JSONDecoder()
    public init(directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Trailfox", isDirectory: true)
        encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }
    public func saveLastScan(_ snapshot: DiagnosticSnapshot) throws { try write(snapshot, name: "last-scan.json") }
    public func loadLastScan() -> DiagnosticSnapshot? { try? read(name: "last-scan.json") }
    public func saveBaseline(_ snapshot: DiagnosticSnapshot, label: String? = nil) throws {
        var copy = snapshot; copy.label = label ?? "Baseline \(Date().formatted(date: .abbreviated, time: .shortened))"
        try write(copy, name: "baseline-\(copy.id.uuidString).json")
    }
    public func baselines() -> [DiagnosticSnapshot] {
        guard let files = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) else { return [] }
        return files.filter { $0.lastPathComponent.hasPrefix("baseline-") }.compactMap { try? decoder.decode(DiagnosticSnapshot.self, from: Data(contentsOf: $0)) }.sorted { $0.completedAt > $1.completedAt }
    }
    private func write(_ snapshot: DiagnosticSnapshot, name: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try encoder.encode(snapshot).write(to: directory.appendingPathComponent(name), options: .atomic)
    }
    private func read(name: String) throws -> DiagnosticSnapshot { try decoder.decode(DiagnosticSnapshot.self, from: Data(contentsOf: directory.appendingPathComponent(name))) }
}
