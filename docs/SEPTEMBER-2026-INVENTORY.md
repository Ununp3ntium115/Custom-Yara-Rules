# Custom-Yara-Rules — September 2026 Inventory (2026-09-30)

This repository is the publish target for Velociraptor Claw Edition's YARA pipeline. The full September goals
inventory for the Claw Edition app lives in the source repository at
`docs/release/SEPTEMBER-2026-GOALS-INVENTORY-2026-09-30.md`. This file covers only this repository.

## Health checks run on 2026-09-30

| Check | Result |
|-------|--------|
| `offline-package/velociraptor-claw-yara-offline.zip` vs `checksums-yara.sha256` | ✅ matches (`2e14bd6f…`) |
| `version.json` vs `checksums-yara.sha256` | ✅ matches |
| `packages/full/combined-rules-master.yar` compiles (libyara 4.5, yara-python) | ✅ 12,414 rules; SHA-256 equals `vendored_engine_filter.source_sha256` |
| `packages/full/combined-rules-vendored-compat.yar` compiles | ✅ 10,788 rules (= `rules_after`) |
| `packages/core/yara-rules-core.yar` compiles | ✅ 5,110 rules |
| Rust `pyro-thor` crate builds | ✅ **fixed in this change**; it did not build before (see below) |
| macOS arm64 / universal build of `pyro-thor` | ✅ **added in this change** (`make macos-universal`, `.github/workflows/build-macos.yml`) |

## Problems found

Fixed in this change:

1. **`Cargo.toml` declared `redb`, `bincode`, `chrono` and `md5` twice.** Cargo rejects the manifest ("duplicate
   key"), so nothing in the crate could build.
2. **12 compile errors in the Rust sources**:
   - `log::info` was called as a function instead of the `log::info!` macro.
   - redb 2.x key borrow types were wrong (`&String` instead of `&str`).
   - `len()` needs the `ReadableTableMetadata` trait in scope.
   - `content` was used after being moved into the struct.
   - `Cow<str>` was passed to `fs::write`.
3. **The `zip` crate pulled in bzip2/zstd C code the code never uses.** It is now `deflate`-only, so the crate
   cross-checks for `aarch64-apple-darwin` from Linux with no C toolchain.
4. **No arm64 target.** The Makefile, `install-targets` and `.kiro/steering/tech.md` listed only x86_64 targets.
   Added `aarch64-apple-darwin`, plus a `macos-universal` lipo target.

Still open (need the pipeline owner / source repo):

5. **`latest.json` is stale.** It is dated 2026-05-15 (`v2026.05.15`, 43,381 rules, a different zip hash), while
   `version.json` and the checksums are from 2026-09-28. Anything reading `latest.json` gets the wrong hash. The
   publisher (`scripts/run-yara-update-local.sh` in the source repo) does not appear to rewrite it.
6. **Two sources silently produce 0 rules.** In `version.json`, `citizenlab` and `macos_specific` both report
   `rule_count: "0"`. Either the fetch is broken or the upstream moved. This matters most for macOS coverage.
7. **`version.json` → `published_repository.offline_package_url` is empty.**
8. **`Custom.Enterprise.Yara.AllRules.yaml` is 0 bytes**, yet it is still shipped at the repo root.
9. **The docs contradict each other on automation.** `docs/CUSTOM-REPO-CONTRACT.md` and `docs/YARA-SETUP.md` say a
   daily GitHub Actions workflow runs at 03:00 UTC. The README says it is local launchd. The source repo records
   GitHub Actions billing as blocked since 2026-03-05.
10. **Legacy identity.** `Cargo.toml` (`authors = ["M507"]`, `repository = …/M507/pyro-thor-yara`), the
    `Custom.*.Yara.AllRules.yaml` artifacts and `.kiro/steering/*` still describe the original Thor/Pyro project,
    not Velociraptor Claw Edition.
11. **Licensing.** The source repo's counsel packet lists YARA source licensing (`t_4a5c367f`, `t_266e5534`) as an
    open App Store blocker. Redistributing third-party rules here falls under the same question.
