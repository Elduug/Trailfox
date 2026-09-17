import SwiftUI
#if SWIFT_PACKAGE
import TrailfoxCore
#endif

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        NavigationSplitView {
            List(selection: $model.selection) {
                Section {
                    Label(DiagnosticCategory.overview.title, systemImage: DiagnosticCategory.overview.symbol).tag(DiagnosticCategory.overview)
                    Label(DiagnosticCategory.findings.title, systemImage: DiagnosticCategory.findings.symbol).tag(DiagnosticCategory.findings)
                }
                Section("Diagnostics") {
                    ForEach([DiagnosticCategory.system, .performance, .storage, .network, .dns, .wifi, .vpn, .processes, .background, .logs, .hardware, .battery, .displays, .security, .updates]) { item in
                        Label(item.title, systemImage: item.symbol).tag(item)
                    }
                }
                Section("History & Output") {
                    Label(DiagnosticCategory.reports.title, systemImage: DiagnosticCategory.reports.symbol).tag(DiagnosticCategory.reports)
                    Label(DiagnosticCategory.baselines.title, systemImage: DiagnosticCategory.baselines.symbol).tag(DiagnosticCategory.baselines)
                }
            }
            .navigationTitle("Trailfox")
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 8) {
                    if model.isScanning { ProgressView(value: model.progress).tint(Color.trailMoss); Text(model.progressText).font(.caption).foregroundStyle(.secondary) }
                    Button { Task { await model.runTriage() } } label: { Label(model.isScanning ? "Triage Running…" : "Run Triage", systemImage: "waveform.path.ecg.rectangle") }.buttonStyle(.borderedProminent).tint(Color.trailMoss).controlSize(.large).frame(maxWidth: .infinity).disabled(model.isScanning)
                }.padding()
            }
        } detail: {
            Group {
                switch model.selection {
                case .overview: OverviewView()
                case .findings: FindingsView()
                case .reports: ReportsView()
                case .baselines: BaselinesView()
                default: DiagnosticDetailView(category: model.selection)
                }
            }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Picker("Presentation", selection: Binding(get: { model.viewMode }, set: model.setViewMode)) { ForEach(ViewMode.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented).frame(width: 210)
                }
            }
        }
        .alert("Trailfox", isPresented: Binding(get: { model.lastError != nil }, set: { if !$0 { model.lastError = nil } })) { Button("OK") {} } message: { Text(model.lastError ?? "") }
    }
}

struct PageHeader: View {
    let title: String, subtitle: String, symbol: String
    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: symbol).font(.system(size: 26, weight: .medium)).foregroundStyle(Color.trailMoss).frame(width: 46, height: 46).background(Color.trailMoss.opacity(0.12), in: RoundedRectangle(cornerRadius: 11))
            VStack(alignment: .leading, spacing: 3) { Text(title).font(.title2.weight(.semibold)); Text(subtitle).foregroundStyle(.secondary) }
            Spacer()
        }
    }
}

struct EmptyScanView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        ContentUnavailableView { Label("Follow the trail", systemImage: "pawprint.fill") } description: { Text("Run a local, read-only triage scan to gather evidence and explain what it means.") } actions: { Button("Run Triage") { Task { await model.runTriage() } }.buttonStyle(.borderedProminent).tint(Color.trailMoss) }
    }
}

struct OverviewView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        if let snapshot = model.snapshot {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) { Text("TRAILFOX").font(.caption.weight(.bold)).tracking(2).foregroundStyle(Color.trailMoss); Text("Mac diagnostics beneath the surface").font(.title.weight(.semibold)); Text("Last scan \(snapshot.completedAt.formatted(date: .abbreviated, time: .shortened)) · local and read-only").foregroundStyle(.secondary) }
                        Spacer(); StatusCount(snapshot: snapshot)
                    }
                    if model.isScanning { ProgressView(value: model.progress).tint(Color.trailMoss); Text(model.progressText).font(.caption).foregroundStyle(.secondary) }
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 255), spacing: 14)], spacing: 14) {
                        OverviewSection(title: "System", symbol: "desktopcomputer", result: snapshot.result(.system), keys: ["model", "architecture", "osVersion", "uptimeDays"])
                        OverviewSection(title: "Performance", symbol: "speedometer", result: snapshot.result(.performance), keys: ["cpu", "memoryPressure", "swap"])
                        OverviewSection(title: "Storage", symbol: "internaldrive", result: snapshot.result(.storage), keys: ["freeBytes", "usedPercent", "timeMachine"])
                        OverviewSection(title: "Network", symbol: "network", result: snapshot.result(.network), keys: ["interface", "ipReachable", "httpsReachable"])
                        OverviewSection(title: "DNS", symbol: "server.rack", result: snapshot.result(.dns), keys: ["dnsWorks", "dnsLatency"])
                        OverviewSection(title: "Security", symbol: "checkmark.shield", result: snapshot.result(.security), keys: ["fileVault", "firewall", "gatekeeper", "sip"])
                    }
                    VStack(alignment: .leading, spacing: 10) {
                        HStack { Text("Findings").font(.headline); Spacer(); Button("View all") { model.selection = .findings } }
                        if snapshot.findings.isEmpty { Label("No rule-based findings require attention", systemImage: "checkmark.circle.fill").foregroundStyle(Color.trailMoss) }
                        ForEach(snapshot.findings.prefix(5)) { FindingRow(finding: $0, compact: true) }
                    }
                }.padding(28)
            }.background(Color(nsColor: .windowBackgroundColor))
        } else { EmptyScanView() }
    }
}

struct StatusCount: View {
    let snapshot: DiagnosticSnapshot
    var attention: Int { snapshot.findings.filter { $0.severity >= .review }.count }
    var body: some View { VStack(alignment: .trailing, spacing: 2) { Text("\(attention)").font(.system(size: 30, weight: .semibold, design: .rounded)).foregroundStyle(attention > 0 ? Color.trailAmber : Color.trailMoss); Text(attention == 1 ? "item needs attention" : "items need attention").font(.caption).foregroundStyle(.secondary) } }
}

struct OverviewSection: View {
    let title: String, symbol: String, result: DiagnosticResult?, keys: [String]
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title.uppercased(), systemImage: symbol).font(.caption.weight(.bold)).foregroundStyle(Color.trailMoss)
            if let result { ForEach(result.metrics.filter { keys.contains($0.id) }) { metric in HStack(alignment: .firstTextBaseline) { Text(metric.label).foregroundStyle(.secondary); Spacer(); Text(metric.value).fontWeight(.medium).lineLimit(1).help(metric.detail ?? metric.value) } } }
            else { Text("Not collected").foregroundStyle(.secondary) }
        }.padding(16).frame(maxWidth: .infinity, minHeight: 126, alignment: .topLeading).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12)).overlay(RoundedRectangle(cornerRadius: 12).stroke(.separator.opacity(0.45)))
    }
}

struct DiagnosticDetailView: View {
    @EnvironmentObject var model: AppModel
    let category: DiagnosticCategory
    var result: DiagnosticResult? { model.snapshot?.result(category) }
    var body: some View {
        if let result {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    PageHeader(title: category.title, subtitle: result.summary, symbol: category.symbol)
                    VStack(spacing: 0) {
                        ForEach(Array(result.metrics.enumerated()), id: \.element.id) { index, metric in
                            HStack(alignment: .top) { Text(metric.label).foregroundStyle(.secondary).frame(width: 190, alignment: .leading); Text(metric.value).textSelection(.enabled); Spacer() }.padding(.vertical, 10)
                            if index < result.metrics.count - 1 { Divider() }
                        }
                    }.padding(.horizontal, 16).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
                    if !result.errors.isEmpty { VStack(alignment: .leading, spacing: 8) { Label("Unavailable data", systemImage: "lock.trianglebadge.exclamationmark").font(.headline).foregroundStyle(Color.trailAmber); ForEach(Array(result.errors.enumerated()), id: \.offset) { _, error in Text(error.message + (error.permissionHint.map { "\n\($0)" } ?? "")).foregroundStyle(.secondary) } }.padding(16).background(Color.trailAmber.opacity(0.08), in: RoundedRectangle(cornerRadius: 12)) }
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Evidence").font(.headline)
                        ForEach(result.evidence) { item in
                            DisclosureGroup { if model.viewMode == .technician { Text(item.technicalDetail.isEmpty ? "No raw detail returned." : item.technicalDetail).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8) } else { Text(item.summary).foregroundStyle(.secondary).padding(.top, 6) } } label: { VStack(alignment: .leading, spacing: 2) { Text(item.title).fontWeight(.medium); Text("Source: \(item.source)").font(.caption).foregroundStyle(.secondary) } }.padding(14).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                        }
                    }
                }.padding(28)
            }
        } else { EmptyScanView() }
    }
}
