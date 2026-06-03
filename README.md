# Velociraptor Claw Edition Custom YARA Rules

This repository is the public package target for the Velociraptor Claw Edition YARA rules pipeline.

**Static package URL:** https://github.com/Ununp3ntium115/Custom-Yara-Rules/releases/download/latest/velociraptor-claw-yara-offline.zip

The URL above is the stable line used by Velociraptor Claw Edition releases and application code. It always points to the latest generated offline YARA package.

## Source Of Truth

Packages in this repository are generated and published from:

- Source repository: https://github.com/Ununp3ntium115/Velociraptor_ClawEdition
- Source script: `scripts/run-yara-update-local.sh` (local) / `.github/workflows/yara-rules-update.yml` (manual)
- Source update script: `scripts/update-yara-rules.sh`
- Source contract path: `yara-rules/custom-repo/`

## Automation

The source build runs on a schedule locally (launchd) and publishes both a dated release and the static `latest` release.

Last synced: 2026-06-03T09:02:15Z
