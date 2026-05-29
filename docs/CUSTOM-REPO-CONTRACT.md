# Velociraptor Claw Edition Custom YARA Rules

This directory defines the README and publish contract for the public `Custom-Yara-Rules` repository.

**Static package URL:** `https://github.com/Ununp3ntium115/Custom-Yara-Rules/releases/download/latest/velociraptor-claw-yara-offline.zip`

The static package URL above is the single stable package line used by Velociraptor Claw Edition releases and application code. It always points to the latest generated offline YARA package.

## Canonical Repository

- Repository: `Ununp3ntium115/Custom-Yara-Rules`
- Local source path in this repo: `yara-rules/`
- Publish contract path in this repo: `yara-rules/custom-repo/`
- Daily workflow: `.github/workflows/yara-rules-update.yml`
- Schedule: `0 3 * * *` UTC

## Source Of Truth

Packages in `Custom-Yara-Rules` are generated and published from this repository:

- Source repository: `https://github.com/Ununp3ntium115/Velociraptor_ClawEdition`
- Source workflow: `.github/workflows/yara-rules-update.yml`
- Source update script: `scripts/update-yara-rules.sh`

## Static Download Paths

- Offline package: `https://github.com/Ununp3ntium115/Custom-Yara-Rules/releases/download/latest/velociraptor-claw-yara-offline.zip`
- Version metadata: `https://github.com/Ununp3ntium115/Custom-Yara-Rules/releases/download/latest/version.json`
- Checksums: `https://github.com/Ununp3ntium115/Custom-Yara-Rules/releases/download/latest/checksums-yara.sha256`

## Synced Repository Paths

The daily workflow updates these paths in `Custom-Yara-Rules`:

| Path | Purpose |
|------|---------|
| `packages/` | Daily generated core, extended, full, and combined YARA rule packages |
| `sources/` | Individual upstream and custom YARA source files |
| `offline-package/` | Latest Velociraptor Claw Edition offline YARA package |
| `vql-artifacts/` | Velociraptor VQL detection artifacts included with the package |
| `detection-data/` | CSV detection data copied from upstream DFIR sources |
| `scripts/update-yara-rules.sh` | Source update script copied from this repo |
| `version.json` | Build timestamp, rule counts, source metadata, and publish target |
| `checksums-yara.sha256` | SHA-256 checksums for release assets |

## Code Consumers

- Electron tool registry: `VelociraptorPlatform-Electron/tools/tools-registry.json`
- macOS updater service: `apps/macos-app/VelociraptorMacOS/Services/YARARulesUpdaterService.swift`
- Package builder: `scripts/update-yara-rules.sh`

Keep those code paths aligned with this contract when changing repository names, release tags, or asset names.

Do not replace the public README with unrelated project text. `Custom-Yara-Rules` exists for Velociraptor Claw Edition package delivery.
