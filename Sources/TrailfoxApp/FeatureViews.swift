import SwiftUI
#if SWIFT_PACKAGE
import TrailfoxCore
#endif

struct FindingsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        if let snapshot = model.snapshot {
            ScrollView { VStack(alignment: .leading, spacing: 18) { PageHeader(title: "Findings", subtitle: "Rule-based explanations traced to collected evidence", symbol: DiagnosticCategory.findings.symbol); if snapshot.findings.isEmpty { ContentUnavailableView("No findings", systemImage: "checkmark.circle", description: Text("The current rules found no items that require attention.")) } else { ForEach(snapshot.findings) { FindingRow(finding: $0) } } }.padding(28) }
        } else { EmptyScanView() }
    }
}

struct FindingRow: View {
    @EnvironmentObject var model: AppModel
    let finding: Finding
    var compact = false
    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 7 : 12) {
            HStack(alignment: .firstTextBaseline) { Image(systemName: finding.severity.symbol).foregroundStyle(finding.severity.color); Text(finding.title).font(.headline); Spacer(); Text(finding.confidence.rawValue + " confidence").font(.caption).foregroundStyle(.secondary) }
            Text(finding.explanation).foregroundStyle(.primary)
            if !compact { Divider(); DetailLabel(title: "Observed", value: finding.observedEvidence); DetailLabel(title: "Likely impact", value: finding.likelyImpact); DetailLabel(title: "Suggested investigation", value: finding.recommendation); if model.viewMode == .technician && !finding.technicalDetails.isEmpty { DetailLabel(title: "Technical details", value: finding.technicalDetails, monospaced: true) } }
        }.padding(compact ? 13 : 17).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12)).overlay(alignment: .leading) { RoundedRectangle(cornerRadius: 3).fill(finding.severity.color).frame(width: 4).padding(.vertical, 8) }
    }
}

struct DetailLabel: View {
    let title: String, value: String
    var monospaced = false
    var body: some View { VStack(alignment: .leading, spacing: 3) { Text(title.uppercased()).font(.caption2.weight(.bold)).foregroundStyle(.secondary); Text(value).font(monospaced ? .system(.callout, design: .monospaced) : .callout).textSelection(.enabled) } }
}

struct ReportsView: View {
    @EnvironmentObject var model: AppModel
    @State private var sanitized = false
    var report: String { model.report(sanitized: sanitized) }
    var body: some View {
        if model.snapshot != nil {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(title: "Reports", subtitle: "Plain text designed for tickets, email, chat, and notes", symbol: DiagnosticCategory.reports.symbol)
                HStack { Toggle("Sanitized", isOn: $sanitized).toggleStyle(.switch); Spacer(); Button { model.copy(model.report(summary: true)) } label: { Label("Copy Summary", systemImage: "doc.on.doc") }; Button { model.copy(report) } label: { Label("Copy Report", systemImage: "doc.on.doc.fill") }; Button { model.saveReport(sanitized: sanitized) } label: { Label("Save Report…", systemImage: "square.and.arrow.down") } }
                TextEditor(text: .constant(report)).font(.system(.callout, design: .monospaced)).scrollContentBackground(.hidden).padding(8).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 10)).overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator))
                Text(sanitized ? "Sensitive identifiers are redacted locally. Review before sharing." : "This report may contain usernames, addresses, hostnames, or other identifiers.").font(.caption).foregroundStyle(.secondary)
            }.padding(28)
        } else { EmptyScanView() }
    }
}

struct BaselinesView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(title: "Baselines", subtitle: "Compare meaningful system changes without noisy differences", symbol: DiagnosticCategory.baselines.symbol)
            HStack { Button { Task { await model.saveBaseline() } } label: { Label("Save Current Scan as Baseline", systemImage: "plus.circle") }.disabled(model.snapshot == nil); Spacer(); Text("\(model.baselines.count) saved").foregroundStyle(.secondary) }
            HSplitView {
                List(model.baselines) { baseline in
                    Button { model.compare(with: baseline) } label: { VStack(alignment: .leading, spacing: 3) { Text(baseline.label ?? "Baseline").fontWeight(.medium); Text(baseline.completedAt.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary) } }.buttonStyle(.plain).padding(.vertical, 4)
                }.frame(minWidth: 230)
                Group {
                    if model.comparison.isEmpty { ContentUnavailableView("Choose a baseline", systemImage: "arrow.left.arrow.right", description: Text("Only material changes in network, DNS, storage, security, battery, background services, and system version are shown.")) }
                    else { List(model.comparison) { item in VStack(alignment: .leading, spacing: 7) { HStack { Label(item.category.title, systemImage: item.category.symbol).font(.headline); Spacer(); Text(item.significance.label).font(.caption).foregroundStyle(item.significance.color) }; Text(item.label).fontWeight(.medium); HStack { Text(item.oldValue).foregroundStyle(.secondary); Image(systemName: "arrow.right"); Text(item.newValue) }.textSelection(.enabled) }.padding(.vertical, 6) } }
                }.frame(minWidth: 430)
            }.clipShape(RoundedRectangle(cornerRadius: 10)).overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator))
        }.padding(28)
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Form {
            Section("Default presentation") { Picker("View", selection: Binding(get: { model.viewMode }, set: model.setViewMode)) { ForEach(ViewMode.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented) }
            Section("Sanitized reports") {
                Toggle("Redact usernames and home paths", isOn: $model.sanitizerOptions.redactUsername)
                Toggle("Redact hostnames", isOn: $model.sanitizerOptions.redactHostname)
                Toggle("Redact IP and MAC addresses", isOn: Binding(get: { model.sanitizerOptions.redactIPAddresses && model.sanitizerOptions.redactMACAddresses }, set: { model.sanitizerOptions.redactIPAddresses = $0; model.sanitizerOptions.redactMACAddresses = $0 }))
                Toggle("Redact email addresses and SSIDs", isOn: Binding(get: { model.sanitizerOptions.redactEmailAddresses && model.sanitizerOptions.redactSSID }, set: { model.sanitizerOptions.redactEmailAddresses = $0; model.sanitizerOptions.redactSSID = $0 }))
            }
            Text("Trailfox performs local, read-only diagnostics and never transmits report data.").font(.caption).foregroundStyle(.secondary)
        }.formStyle(.grouped).padding()
    }
}
