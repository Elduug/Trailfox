import Foundation

public struct CommandResult: Sendable, Equatable {
    public let executable: String
    public let arguments: [String]
    public let stdout: String
    public let stderr: String
    public let exitCode: Int32
    public let duration: TimeInterval
    public let timedOut: Bool
    public var succeeded: Bool { exitCode == 0 && !timedOut }
}

public enum CommandRunnerError: LocalizedError, Sendable {
    case executableNotAllowed(String)
    case launchFailed(String)
    public var errorDescription: String? {
        switch self {
        case .executableNotAllowed(let path): "Executable is outside Trailfox's allowlist: \(path)"
        case .launchFailed(let detail): "Could not launch diagnostic command: \(detail)"
        }
    }
}

public struct CommandRunner: Sendable {
    public static let allowedPrefixes = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/"]
    public init() {}

    public func run(_ executable: String, _ arguments: [String] = [], timeout: TimeInterval = 8) async throws -> CommandResult {
        guard Self.allowedPrefixes.contains(where: executable.hasPrefix) else { throw CommandRunnerError.executableNotAllowed(executable) }
        return try await Task.detached(priority: .utility) {
            let process = Process()
            let output = Pipe(), error = Pipe()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            process.standardOutput = output
            process.standardError = error
            let started = Date()
            do { try process.run() } catch { throw CommandRunnerError.launchFailed(error.localizedDescription) }
            let deadline = Date().addingTimeInterval(timeout)
            while process.isRunning && Date() < deadline {
                if Task.isCancelled { process.terminate(); throw CancellationError() }
                try await Task.sleep(for: .milliseconds(30))
            }
            let timedOut = process.isRunning
            if timedOut { process.terminate() }
            process.waitUntilExit()
            let outData = output.fileHandleForReading.readDataToEndOfFile()
            let errData = error.fileHandleForReading.readDataToEndOfFile()
            return CommandResult(
                executable: executable, arguments: arguments,
                stdout: String(decoding: outData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
                stderr: String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
                exitCode: process.terminationStatus, duration: Date().timeIntervalSince(started), timedOut: timedOut
            )
        }.value
    }
}

public protocol DiagnosticCollector: Sendable {
    var category: DiagnosticCategory { get }
    var name: String { get }
    func collect() async -> DiagnosticResult
}

public enum Parse {
    public static func firstValue(_ text: String, after key: String) -> String? {
        text.split(separator: "\n").map(String.init).first { $0.localizedCaseInsensitiveContains(key) }?
            .split(separator: ":", maxSplits: 1).dropFirst().first.map { $0.trimmingCharacters(in: .whitespaces) }
    }
    public static func bytes(_ value: String) -> Int64? {
        let digits = value.filter { $0.isNumber }
        return Int64(digits)
    }
    public static func percent(_ part: Double, of total: Double) -> String {
        guard total > 0 else { return "Unavailable" }
        return String(format: "%.0f%%", part / total * 100)
    }
    public static func humanBytes(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
