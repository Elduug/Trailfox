import Foundation

public struct NetworkCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.network
    public let name = "Network"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let route = runner.run("/sbin/route", ["-n", "get", "default"], timeout: 4)
            async let interfaces = runner.run("/sbin/ifconfig", timeout: 6)
            async let reach = runner.run("/sbin/ping", ["-c", "2", "-W", "1500", "1.1.1.1"], timeout: 6)
            async let https = runner.run("/usr/bin/curl", ["-I", "--max-time", "6", "https://captive.apple.com/hotspot-detect.html"], timeout: 8)
            async let proxy = runner.run("/usr/sbin/scutil", ["--proxy"], timeout: 3)
            let (r, i, p, h, x) = try await (route, interfaces, reach, https, proxy)
            let gateway = Parse.firstValue(r.stdout, after: "gateway") ?? "Unavailable"
            let interface = Parse.firstValue(r.stdout, after: "interface") ?? "Unavailable"
            let packetLine = p.stdout.split(separator: "\n").first { $0.contains("packet loss") }.map(String.init) ?? "Test unavailable"
            return DiagnosticResult(category: category, summary: p.succeeded && h.succeeded ? "Internet reachable" : "Connectivity needs review",
                metrics: [Metric(id: "interface", label: "Active Interface", value: interface), Metric(id: "gateway", label: "Gateway", value: gateway, sensitive: true), Metric(id: "ipReachable", label: "Internet by IP", value: p.succeeded ? "Reachable" : "Unreachable"), Metric(id: "httpsReachable", label: "HTTPS", value: h.succeeded ? "Reachable" : "Unreachable"), Metric(id: "packetLoss", label: "Packet Test", value: packetLine)],
                evidence: [Evidence(category: category, title: "Network route and reachability", summary: "Default route, interfaces, IP reachability, HTTPS, and proxy state were checked.", technicalDetail: r.stdout + "\n\n" + p.stdout + "\n\nProxies:\n" + x.stdout + "\n\nInterfaces:\n" + i.stdout, source: "route, ifconfig, ping, curl, scutil")])
        } catch { return DiagnosticResult(category: category, summary: "Network test unavailable", errors: [CollectorError(error.localizedDescription, permissionHint: "Some network details may be restricted by system policy.")]) }
    }
}

public struct DNSCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.dns
    public let name = "DNS"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let config = runner.run("/usr/sbin/scutil", ["--dns"], timeout: 5)
            async let a = runner.run("/usr/bin/dscacheutil", ["-q", "host", "-a", "name", "apple.com"], timeout: 6)
            async let aaaa = runner.run("/usr/bin/dscacheutil", ["-q", "host", "-a", "name", "cloudflare.com"], timeout: 6)
            let started = Date(); let (c, one, two) = try await (config, a, aaaa); let elapsed = Date().timeIntervalSince(started)
            let nameservers = c.stdout.split(separator: "\n").filter { $0.contains("nameserver[") }.map { $0.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? "" }
            let success = one.succeeded && !one.stdout.isEmpty && two.succeeded && !two.stdout.isEmpty
            return DiagnosticResult(category: category, summary: success ? "DNS resolution is working" : "DNS resolution failed",
                metrics: [Metric(id: "dnsWorks", label: "Resolution", value: success ? "Working" : "Failed"), Metric(id: "dnsServers", label: "Resolvers", value: nameservers.isEmpty ? "Unavailable" : nameservers.prefix(4).joined(separator: ", "), sensitive: true), Metric(id: "dnsLatency", label: "Combined Test Time", value: String(format: "%.0f ms", elapsed * 1000))],
                evidence: [Evidence(category: category, title: "DNS resolution tests", summary: "Two external names were resolved using the macOS resolver stack.", technicalDetail: c.stdout + "\n\napple.com:\n" + one.stdout + "\n\ncloudflare.com:\n" + two.stdout, source: "scutil, dscacheutil")])
        } catch { return DiagnosticResult(category: category, summary: "DNS test unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}

public struct WiFiCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.wifi
    public let name = "Wi-Fi"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            let result = try await runner.run("/usr/sbin/system_profiler", ["SPAirPortDataType", "-detailLevel", "mini"], timeout: 12)
            let state = result.stdout.contains("Current Network Information") ? "Connected" : "Not connected or unavailable"
            return DiagnosticResult(category: category, summary: state,
                metrics: [Metric(id: "wifiState", label: "State", value: state), Metric(id: "wifiPrivacy", label: "Network name", value: "Hidden by macOS privacy controls", detail: "SSID/BSSID may require Location Services permission.")],
                evidence: [Evidence(category: category, title: "Wi-Fi interface", summary: "Publicly available Wi-Fi adapter state was collected.", technicalDetail: result.stdout, source: "system_profiler")])
        } catch { return DiagnosticResult(category: category, summary: "Wi-Fi details unavailable", errors: [CollectorError(error.localizedDescription, permissionHint: "Location Services can affect SSID and BSSID availability.")]) }
    }
}

public struct VPNCollector: DiagnosticCollector {
    public let category = DiagnosticCategory.vpn
    public let name = "VPN / Tunnels"
    private let runner = CommandRunner()
    public init() {}
    public func collect() async -> DiagnosticResult {
        do {
            async let interfaces = runner.run("/sbin/ifconfig", ["-l"], timeout: 4)
            async let extensions = runner.run("/usr/bin/systemextensionsctl", ["list"], timeout: 8)
            async let proxies = runner.run("/usr/sbin/scutil", ["--proxy"], timeout: 4)
            let (i, e, p) = try await (interfaces, extensions, proxies)
            let tunnels = i.stdout.split(separator: " ").filter { $0.hasPrefix("utun") }
            return DiagnosticResult(category: category, summary: "\(tunnels.count) tunnel interface\(tunnels.count == 1 ? "" : "s") active",
                metrics: [Metric(id: "tunnelCount", label: "Active Tunnels", value: "\(tunnels.count)"), Metric(id: "tunnels", label: "Interfaces", value: tunnels.isEmpty ? "None" : tunnels.joined(separator: ", "))],
                evidence: [Evidence(category: category, title: "Network extensions and tunnels", summary: "Tunnel interfaces are not treated as a problem by themselves.", technicalDetail: e.stdout + "\n\n" + p.stdout, source: "ifconfig, systemextensionsctl, scutil")])
        } catch { return DiagnosticResult(category: category, summary: "Tunnel details unavailable", errors: [CollectorError(error.localizedDescription)]) }
    }
}
