import Foundation

public enum DiagnosticCategory: String, Codable, CaseIterable, Sendable, Identifiable {
    case overview, system, performance, storage, network, dns, wifi, vpn, processes
    case background = "Login & Background Items"
    case logs = "Logs & Errors"
    case hardware, battery
    case displays = "Displays & Input"
    case security, updates, findings, reports, baselines

    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .dns: "DNS"
        case .wifi: "Wi-Fi"
        case .vpn: "VPN / Network Extensions"
        default: rawValue.capitalized
        }
    }
    public var symbol: String {
        switch self {
        case .overview: "gauge.with.dots.needle.50percent"
        case .system: "desktopcomputer"
        case .performance: "speedometer"
        case .storage: "internaldrive"
        case .network: "network"
        case .dns: "server.rack"
        case .wifi: "wifi"
        case .vpn: "lock.shield"
        case .processes: "list.bullet.rectangle"
        case .background: "gearshape.2"
        case .logs: "doc.text.magnifyingglass"
        case .hardware: "cpu"
        case .battery: "battery.75percent"
        case .displays: "display"
        case .security: "checkmark.shield"
        case .updates: "arrow.triangle.2.circlepath"
        case .findings: "exclamationmark.bubble"
        case .reports: "doc.plaintext"
        case .baselines: "clock.arrow.circlepath"
        }
    }
}

public enum Severity: Int, Codable, CaseIterable, Comparable, Sendable {
    case healthy = 0, informational, review, warning, critical
    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }
    public var label: String {
        switch self {
        case .healthy: "Healthy"
        case .informational: "Informational"
        case .review: "Review"
        case .warning: "Warning"
        case .critical: "Critical"
        }
    }
}

public enum EvidenceConfidence: String, Codable, Sendable { case strong = "Strong", moderate = "Moderate", weak = "Weak" }
public enum ViewMode: String, Codable, Sendable, CaseIterable { case basic = "Basic", technician = "Technician" }

public struct Metric: Identifiable, Codable, Hashable, Sendable {
    public var id: String
    public var label: String
    public var value: String
    public var detail: String?
    public var sensitive: Bool
    public init(id: String, label: String, value: String, detail: String? = nil, sensitive: Bool = false) {
        self.id = id; self.label = label; self.value = value; self.detail = detail; self.sensitive = sensitive
    }
}

public struct Evidence: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var category: DiagnosticCategory
    public var title: String
    public var summary: String
    public var technicalDetail: String
    public var timestamp: Date
    public var source: String
    public init(id: UUID = UUID(), category: DiagnosticCategory, title: String, summary: String, technicalDetail: String = "", timestamp: Date = Date(), source: String) {
        self.id = id; self.category = category; self.title = title; self.summary = summary
        self.technicalDetail = technicalDetail; self.timestamp = timestamp; self.source = source
    }
}

public struct CollectorError: Codable, Hashable, Sendable {
    public var message: String
    public var permissionHint: String?
    public init(_ message: String, permissionHint: String? = nil) { self.message = message; self.permissionHint = permissionHint }
}

public struct DiagnosticResult: Identifiable, Codable, Sendable {
    public var id: UUID
    public var category: DiagnosticCategory
    public var summary: String
    public var metrics: [Metric]
    public var evidence: [Evidence]
    public var errors: [CollectorError]
    public var collectedAt: Date
    public init(id: UUID = UUID(), category: DiagnosticCategory, summary: String, metrics: [Metric] = [], evidence: [Evidence] = [], errors: [CollectorError] = [], collectedAt: Date = Date()) {
        self.id = id; self.category = category; self.summary = summary; self.metrics = metrics
        self.evidence = evidence; self.errors = errors; self.collectedAt = collectedAt
    }
    public func metric(_ id: String) -> String? { metrics.first { $0.id == id }?.value }
}

public struct Finding: Identifiable, Codable, Sendable {
    public var id: UUID
    public var title: String
    public var category: DiagnosticCategory
    public var severity: Severity
    public var confidence: EvidenceConfidence
    public var explanation: String
    public var observedEvidence: String
    public var likelyImpact: String
    public var recommendation: String
    public var technicalDetails: String
    public var relatedEvidenceIDs: [UUID]
    public var timestamp: Date
    public init(id: UUID = UUID(), title: String, category: DiagnosticCategory, severity: Severity, confidence: EvidenceConfidence, explanation: String, observedEvidence: String, likelyImpact: String, recommendation: String, technicalDetails: String = "", relatedEvidenceIDs: [UUID] = [], timestamp: Date = Date()) {
        self.id = id; self.title = title; self.category = category; self.severity = severity; self.confidence = confidence
        self.explanation = explanation; self.observedEvidence = observedEvidence; self.likelyImpact = likelyImpact
        self.recommendation = recommendation; self.technicalDetails = technicalDetails; self.relatedEvidenceIDs = relatedEvidenceIDs; self.timestamp = timestamp
    }
}

public struct DiagnosticSnapshot: Identifiable, Codable, Sendable {
    public var id: UUID
    public var startedAt: Date
    public var completedAt: Date
    public var results: [DiagnosticResult]
    public var findings: [Finding]
    public var label: String?
    public init(id: UUID = UUID(), startedAt: Date, completedAt: Date = Date(), results: [DiagnosticResult], findings: [Finding] = [], label: String? = nil) {
        self.id = id; self.startedAt = startedAt; self.completedAt = completedAt; self.results = results; self.findings = findings; self.label = label
    }
    public func result(_ category: DiagnosticCategory) -> DiagnosticResult? { results.first { $0.category == category } }
}

public struct BaselineChange: Identifiable, Codable, Sendable {
    public var id = UUID()
    public var category: DiagnosticCategory
    public var label: String
    public var oldValue: String
    public var newValue: String
    public var significance: Severity
    public init(category: DiagnosticCategory, label: String, oldValue: String, newValue: String, significance: Severity = .review) {
        self.category = category; self.label = label; self.oldValue = oldValue; self.newValue = newValue; self.significance = significance
    }
}
