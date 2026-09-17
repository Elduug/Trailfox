import Foundation
import Testing
#if SWIFT_PACKAGE
@testable import TrailfoxCore
#endif

private func snapshot(_ results: [DiagnosticResult]) -> DiagnosticSnapshot {
    DiagnosticSnapshot(startedAt: Date(), results: results)
}

@Test func lowDiskFindingIsCritical() {
    let storage = DiagnosticResult(category: .storage, summary: "low", metrics: [Metric(id: "freeBytes", label: "Free Space", value: "5 GB", detail: "5000000000")])
    let findings = FindingsEngine().evaluate(snapshot([storage]))
    #expect(findings.first(where: { $0.category == .storage })?.severity == .critical)
}

@Test func dnsCorrelationIsStrongWhenIPWorks() {
    let dns = DiagnosticResult(category: .dns, summary: "failed", metrics: [Metric(id: "dnsWorks", label: "Resolution", value: "Failed")])
    let network = DiagnosticResult(category: .network, summary: "up", metrics: [Metric(id: "ipReachable", label: "Internet by IP", value: "Reachable")])
    let finding = FindingsEngine().evaluate(snapshot([dns, network])).first { $0.category == .dns }
    #expect(finding?.confidence == .strong); #expect(finding?.severity == .warning)
}

@Test func healthyStorageDoesNotCreateFinding() {
    let storage = DiagnosticResult(category: .storage, summary: "ok", metrics: [Metric(id: "freeBytes", label: "Free Space", value: "200 GB", detail: "200000000000")])
    #expect(!FindingsEngine().evaluate(snapshot([storage])).contains { $0.category == .storage })
}

@Test func sanitizerRedactsCommonIdentifiers() {
    let input = "User /Users/\(NSUserName())/Library host@example.com 192.168.1.20 aa:bb:cc:dd:ee:ff SSID: OfficeWiFi"
    let output = ReportSanitizer().sanitize(input)
    #expect(!output.contains("192.168.1.20")); #expect(!output.contains("aa:bb:cc:dd:ee:ff")); #expect(!output.contains("host@example.com")); #expect(output.contains("/Users/<user>/")); #expect(output.contains("SSID: <ssid>"))
}

@Test func baselineSuppressesSmallStorageChanges() {
    let old = snapshot([DiagnosticResult(category: .storage, summary: "", metrics: [Metric(id: "freeBytes", label: "Free", value: "50 GB", detail: "50000000000")])])
    let new = snapshot([DiagnosticResult(category: .storage, summary: "", metrics: [Metric(id: "freeBytes", label: "Free", value: "49 GB", detail: "49000000000")])])
    #expect(BaselineComparator().compare(old, new).isEmpty)
}

@Test func baselineReportsDNSChange() {
    let old = snapshot([DiagnosticResult(category: .dns, summary: "", metrics: [Metric(id: "dnsServers", label: "Resolvers", value: "1.1.1.1")])])
    let new = snapshot([DiagnosticResult(category: .dns, summary: "", metrics: [Metric(id: "dnsServers", label: "Resolvers", value: "9.9.9.9")])])
    #expect(BaselineComparator().compare(old, new).count == 1)
}

@Test func logGroupingSuppressesChangingIdentifiers() {
    let groups = LogGrouper.group(lines: ["2026-01-01 service failed request 1234 deadbeef", "2026-01-02 service failed request 9834 cafebabe"])
    #expect(groups.count == 1); #expect(groups[0].count == 2)
}

@Test func reportContainsTraceableFinding() {
    var value = snapshot([])
    value.findings = [Finding(title: "Test finding", category: .system, severity: .review, confidence: .strong, explanation: "Plain explanation", observedEvidence: "Observed evidence", likelyImpact: "Impact", recommendation: "Review it")]
    let report = ReportGenerator().fullReport(for: value)
    #expect(report.contains("Observed evidence")); #expect(report.contains("Suggested investigation: Review it"))
}

@Test func commandRunnerRejectsArbitraryExecutable() async {
    await #expect(throws: CommandRunnerError.self) { _ = try await CommandRunner().run("/Applications/tool", timeout: 1) }
}
