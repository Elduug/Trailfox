# Trailfox

[![License: MIT](https://img.shields.io/badge/License-MIT-2f6f4e.svg)](LICENSE)
[![Platform: macOS 14+](https://img.shields.io/badge/macOS-14%2B-496c5a.svg)](#requirements)
[![Swift 6](https://img.shields.io/badge/Swift-6-F05138.svg)](https://www.swift.org/)

**Mac diagnostics beneath the surface**

Trailfox is a native, local-first macOS troubleshooting utility. It collects system health evidence, correlates related failures, explains findings in plain language, and produces ticket-friendly technical and sanitized reports. Version 1 is deliberately read-only: it does not kill processes, change network settings, remove files, restart services, or transmit diagnostic data.

## Requirements

- macOS 14 or later
- Apple Silicon (primary) or Intel Mac
- Xcode 16 or later for the Xcode project
- Swift 6 toolchain for Swift Package Manager builds

## Build and run

### Xcode

1. Open `Trailfox.xcodeproj`.
2. Select the **Trailfox** scheme and **My Mac** destination.
3. Press Run.
4. Click **Run Triage** in the sidebar.

The Xcode target uses native SwiftUI and macOS frameworks, compiles the app icon asset catalog, and requires no third-party packages.

### Command line

```sh
swift build --product Trailfox
swift test
scripts/package-app.sh
open build/Trailfox.app
```

The package script creates and ad-hoc signs a development app bundle. A normal Xcode archive should be used for distribution signing and notarization.

To exercise real collectors without the UI:

```sh
swift run trailfox-smoke
```

The smoke runner exits unsuccessfully if fewer than ten diagnostic sections complete. Individual collector errors still appear in the report rather than aborting the scan.

## Current features

- Polished native sidebar interface with an Everforest-inspired palette
- Overview dashboard and separate diagnostic sections
- Concurrent, isolated system, performance, storage, network, DNS, Wi-Fi, tunnel, process, background-item, log, crash, security, battery, hardware, display, and update collectors
- Gateway, public-IP, HTTPS, DNS, packet-loss, and resolver checks
- VPN/tunnel and network-extension inventory without assuming that a VPN is a fault
- Filtered and duplicate-grouped Unified Log evidence
- Recent crash/panic report indexing and grouping
- Deterministic findings engine with evidence, confidence, impact, and investigation guidance
- Cross-subsystem DNS correlation and meaningful storage, uptime, tunnel, crash, security, and collector-health rules
- Basic and Technician presentations over the same structured data
- Copyable summary, full technical report, local text export, and configurable sanitized export
- Persistent last scan and named snapshot baselines
- Baseline comparison with noisy storage changes suppressed
- Generated red-fox forest app icon
- Nine deterministic tests covering rules, severity, correlation, sanitization, baselines, log grouping, reporting, and command safety

## Permissions and privacy

Trailfox is useful as a normal user. macOS may hide some SSID/BSSID details without Location Services and may restrict Unified Log, background-item, security, management, and crash-report data. Trailfox shows an unavailable state and continues the scan; it does not request administrator privileges automatically.

Reports can contain hostnames, usernames, paths, network addresses, SSIDs, or application details. Use **Sanitized** before sharing externally, and review the result. All processing and persistence happen locally under the user's Application Support directory.

## Architecture

`TrailfoxCore` contains no UI and is also consumed by the smoke runner and tests.

- `Models.swift`: structured results, evidence, findings, snapshots, and baseline changes
- `CommandRunner.swift`: argument-separated async command execution with allowlisting, timeouts, cancellation, stdout/stderr, and exit status
- `Collectors/`: isolated diagnostic modules; one failure cannot terminate triage
- `TriageService.swift`: concurrent collection, result merging, progress, and findings evaluation
- `Analysis/`: separately testable rule-based findings and correlation logic
- `Reporting/`: plain-text report generation and configurable redaction
- `Persistence/`: atomic JSON snapshots and noise-aware baseline comparison
- `TrailfoxApp/`: native SwiftUI navigation, dashboards, details, reports, baselines, and settings

The findings engine does not depend on AI. Every finding is derived from stored metrics or evidence.

## System commands

Commands are invoked directly with an executable URL and argument array—never through `/bin/sh -c`.

| Command | Purpose |
| --- | --- |
| `system_profiler` | Hardware, software, Wi-Fi, power, displays, peripherals, and install history |
| `sysctl`, `top`, `vm_stat`, `ps` | CPU, memory, swap, load, and processes |
| `df`, `diskutil`, `tmutil` | Capacity, attached disks, and Time Machine status |
| `route`, `ifconfig`, `ping`, `curl` | Routes, interfaces, reachability, loss, and HTTPS |
| `scutil`, `dscacheutil` | Resolver, DNS, and proxy state |
| `systemextensionsctl` | Network/system extensions |
| `launchctl`, `sfltool` | Loaded services and registered background items |
| `log` | Narrow, time-bounded Unified Log query |
| `fdesetup`, `socketfilterfw`, `spctl`, `csrutil`, `profiles` | Security and enrollment status |
| `pmset` | Battery and power state |

Each command has a bounded timeout. Slow or restricted commands produce partial/unavailable evidence rather than crashing the app.

## Known limitations

- Wi-Fi SSID/BSSID and detailed radio metrics depend on macOS privacy policy and available public interfaces.
- Crash analysis groups report names and timestamps; it does not yet parse every vendor-specific crash-report schema.
- The quick triage records update history and automatic-check state but intentionally does not run a slow `softwareupdate --list` query.
- Deep directory-size analysis is not part of quick triage.
- The interactive input test is represented in the architecture but is not implemented in version 1.
- Baseline comparison currently covers high-signal metrics rather than every collected field.
- Full Disk Access can improve some log and diagnostic-report visibility, but it is not required.

## Verification

The repository was verified with a Swift 6 build, nine passing tests, a real collector smoke run (15 merged sections), report generation, app-bundle validation, and ad-hoc code-sign verification. The machine used for the final verification had an internally mismatched Command Line Tools compiler/SDK and no full Xcode installation; a temporary unmodified-system SDK copy was used to perform the build. This workaround is not needed on a normal matching Xcode installation.

See [Architecture notes](docs/ARCHITECTURE.md) for data flow and extension points.

## Contributing

Bug reports and focused pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before contributing and report security or privacy issues through the process in [SECURITY.md](SECURITY.md).

## License and author

Trailfox is available under the [MIT License](LICENSE), including its original project artwork unless a file says otherwise.

Created and maintained by [Jake Carter](https://github.com/Elduug) ([@Elduug](https://github.com/Elduug)).
