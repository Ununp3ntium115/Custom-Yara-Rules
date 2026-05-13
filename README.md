# Velociraptor Claw Edition Custom YARA Rules

This repository is the public package target for the Velociraptor Claw Edition YARA rules pipeline.

**Static package URL:** `https://github.com/Ununp3ntium115/Custom-Yara-Rules/releases/download/latest/velociraptor-claw-yara-offline.zip`

The URL above is the stable line used by Velociraptor Claw Edition releases and application code. It always points to the latest generated offline YARA package.

## Source Of Truth

Packages in this repository are generated and published from:

- Source repository: `https://github.com/Ununp3ntium115/Velociraptor_ClawEdition`
- Source workflow: `.github/workflows/yara-rules-update.yml`
- Source update script: `scripts/update-yara-rules.sh`
- Source contract path: `yara-rules/custom-repo/`

## Repository Paths

| Path | Purpose |
|------|---------|
| `packages/` | Daily generated core, extended, full, and combined YARA rule packages |
| `sources/` | Individual upstream and custom YARA source files |
| `offline-package/` | Latest Velociraptor Claw Edition offline YARA package |
| `vql-artifacts/` | Velociraptor VQL detection artifacts included with the package |
| `detection-data/` | CSV detection data copied from upstream DFIR sources |
| `scripts/update-yara-rules.sh` | Source update script copied from Velociraptor Claw Edition |
| `version.json` | Build timestamp, rule counts, source metadata, and publish target |
| `checksums-yara.sha256` | SHA-256 checksums for release assets |

## Automation

The Velociraptor Claw Edition source workflow runs every day at 03:00 UTC, updates this repository's code paths, then publishes both a dated release and the static `latest` release.

Do not replace this README with unrelated project text. This repository exists for Velociraptor Claw Edition package delivery.
