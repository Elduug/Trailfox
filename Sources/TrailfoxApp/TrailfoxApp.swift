import SwiftUI
#if SWIFT_PACKAGE
import TrailfoxCore
#endif

@main
struct TrailfoxApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(model).frame(minWidth: 1040, minHeight: 680)
        }
        .commands {
            CommandGroup(after: .newItem) { Button("Run Triage") { Task { await model.runTriage() } }.keyboardShortcut("r", modifiers: [.command, .shift]).disabled(model.isScanning) }
        }
        Settings { SettingsView().environmentObject(model).frame(width: 500, height: 320) }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var selection: DiagnosticCategory = .overview
    @Published var snapshot: DiagnosticSnapshot?
    @Published var baselines: [DiagnosticSnapshot] = []
    @Published var comparison: [BaselineChange] = []
    @Published var isScanning = false
    @Published var progress = 0.0
    @Published var progressText = "Ready"
    @Published var viewMode: ViewMode = UserDefaults.standard.string(forKey: "viewMode").flatMap(ViewMode.init(rawValue:)) ?? .basic
    @Published var sanitizerOptions = SanitizerOptions()
    @Published var lastError: String?
    let store = SnapshotStore()
    private let service = TriageService()

    init() { Task { snapshot = await store.loadLastScan(); baselines = await store.baselines() } }
    func runTriage() async {
        guard !isScanning else { return }
        isScanning = true; progress = 0; comparison = []; lastError = nil
        let value = await service.run { text, amount in await self.updateProgress(text, amount) }
        snapshot = value; isScanning = false; progressText = "Completed \(value.completedAt.formatted(date: .omitted, time: .shortened))"
        do { try await store.saveLastScan(value) } catch { lastError = error.localizedDescription }
    }
    private func updateProgress(_ text: String, _ amount: Double) { progressText = text; progress = amount }
    func saveBaseline() async {
        guard let snapshot else { return }
        do { try await store.saveBaseline(snapshot); baselines = await store.baselines() } catch { lastError = error.localizedDescription }
    }
    func compare(with baseline: DiagnosticSnapshot) { guard let snapshot else { return }; comparison = BaselineComparator().compare(baseline, snapshot) }
    func setViewMode(_ mode: ViewMode) { viewMode = mode; UserDefaults.standard.set(mode.rawValue, forKey: "viewMode") }
    func copy(_ text: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string) }
    func report(sanitized: Bool = false, summary: Bool = false) -> String {
        guard let snapshot else { return "Run a triage scan to generate a report." }
        let text = summary ? ReportGenerator().summary(for: snapshot) : ReportGenerator().fullReport(for: snapshot)
        return sanitized ? ReportSanitizer(options: sanitizerOptions).sanitize(text, snapshot: snapshot) : text
    }
    func saveReport(sanitized: Bool) {
        let panel = NSSavePanel(); panel.nameFieldStringValue = sanitized ? "Trailfox-Sanitized-Report.txt" : "Trailfox-Report.txt"; panel.allowedContentTypes = [.plainText]
        if panel.runModal() == .OK, let url = panel.url { do { try report(sanitized: sanitized).write(to: url, atomically: true, encoding: .utf8) } catch { lastError = error.localizedDescription } }
    }
}
