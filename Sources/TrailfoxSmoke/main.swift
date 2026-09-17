import Foundation
import TrailfoxCore

@main
struct TrailfoxSmoke {
    static func main() async {
        let snapshot = await TriageService().run { name, value in
            FileHandle.standardError.write(Data("[\(Int(value * 100))%] \(name)\n".utf8))
        }
        print(ReportGenerator().summary(for: snapshot))
        print("\nCollected \(snapshot.results.count) sections and produced \(snapshot.findings.count) findings.")
        exit(snapshot.results.count >= 10 ? 0 : 1)
    }
}
