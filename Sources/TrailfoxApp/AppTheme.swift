import SwiftUI
#if SWIFT_PACKAGE
import TrailfoxCore
#endif

extension Color {
    init(hex: Int) { self.init(red: Double((hex >> 16) & 255) / 255, green: Double((hex >> 8) & 255) / 255, blue: Double(hex & 255) / 255) }
    static let trailForest = Color(hex: TrailfoxTheme.forestHex), trailDeep = Color(hex: TrailfoxTheme.evergreenHex)
    static let trailMoss = Color(hex: TrailfoxTheme.mossHex), trailSage = Color(hex: TrailfoxTheme.sageHex)
    static let trailAmber = Color(hex: TrailfoxTheme.amberHex), trailRust = Color(hex: TrailfoxTheme.rustHex), trailCream = Color(hex: TrailfoxTheme.creamHex)
}

extension Severity {
    var color: Color { switch self { case .critical: .red; case .warning: .trailRust; case .review: .trailAmber; case .informational: .trailSage; case .healthy: .trailMoss } }
    var symbol: String { switch self { case .critical: "exclamationmark.octagon.fill"; case .warning: "exclamationmark.triangle.fill"; case .review: "eye.fill"; case .informational: "info.circle.fill"; case .healthy: "checkmark.circle.fill" } }
}
