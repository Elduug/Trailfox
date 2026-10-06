# Contributing to Trailfox

Thank you for helping improve Trailfox.

## Before opening an issue

- Search existing issues first.
- Include the macOS, Xcode, and Swift versions involved.
- Remove usernames, hostnames, IP addresses, serial numbers, SSIDs, organization names, and other private diagnostic data from screenshots and reports.
- Use GitHub's private security reporting flow for security or privacy vulnerabilities.

## Development workflow

1. Fork the repository and create a focused branch.
2. Keep collectors read-only, bounded by timeouts, and isolated from one another.
3. Add or update deterministic tests when behavior changes.
4. Run `swift build`, `swift test`, and—when collector behavior changes—`swift run trailfox-smoke`.
5. Open a pull request explaining the user-facing behavior and verification performed.

By contributing, you agree that your contribution is licensed under the repository's MIT License.
