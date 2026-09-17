# Trailfox architecture

## Scan flow

1. `AppModel` asks `TriageService` to run.
2. The service executes independent `DiagnosticCollector` values concurrently.
3. Every collector returns a `DiagnosticResult`, including partial metrics and recoverable errors.
4. Results sharing a category (currently Unified Log and crash indexing) are merged.
5. `FindingsEngine` evaluates separate `FindingRule` values over the complete snapshot.
6. The snapshot is persisted atomically as JSON and rendered in Basic or Technician view.
7. `ReportGenerator` creates text; `ReportSanitizer` optionally redacts identifiers.

## Safety boundaries

- `CommandRunner` only accepts absolute executables beneath approved macOS command directories.
- Executable and arguments are always separate.
- No collector accepts or interpolates user input into a command.
- Commands have time limits and cancellation checks.
- Collectors are read-only and return errors as data.
- Sanitization runs locally after report creation.

## Adding a collector

1. Add a `DiagnosticCollector` conformer under `Sources/TrailfoxCore/Collectors`.
2. Return stable metric IDs because findings and baselines depend on them.
3. Preserve raw output in `Evidence.technicalDetail` and write a short Basic-view summary.
4. Convert permission restrictions into `CollectorError` with a useful hint.
5. Register the collector in `TriageService.standardCollectors`.
6. Add parsing and rule tests before adding a finding.

## Adding a rule

Implement `FindingRule` separately from collection. Use multiple facts only when they materially improve confidence, preserve related evidence IDs when available, and distinguish correlation from proven cause. Core rules must stay deterministic.

## Persistence

Snapshots are version-tolerant Codable JSON values stored in `~/Library/Application Support/Trailfox`. Baselines are independent snapshots. Comparison uses a high-signal allowlist and per-metric noise suppression so volatile values do not overwhelm useful changes.
