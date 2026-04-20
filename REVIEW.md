# 🔎 Repository Review (2026-04-10)

## Scope Reviewed
- `bin/verifiedtrust.sh`
- `plugins/*.sh`
- `README.md`

## Strengths
1. **Clear top-level workflow and output paths** in `README.md`, including options and plugin behavior.
2. **Defensive shell settings** (`set -euo pipefail`) in the main scanner.
3. **Modular plugin system** with simple `plugin_main` contract and per-account environment (`PLUGIN_USER`).
4. **Multiple export targets** (CSV/JSON/HTML/PDF) and MDM-focused summary modes.

## Findings

### High Priority
1. **`-u` UID filter is not applied to scanning logic**
   - The script parses `-u <min,max>`, but account scanning is hard-coded to daemon `<500` and user `>=500` buckets.
   - Result: custom UID ranges only affect a proof listing section, not actual risk/effort results.

2. **Parallel execution gate is effectively always true when GNU parallel exists**
   - Condition uses `[[ -n "$PARALLEL" ]] || true`, which always succeeds.
   - Result: script may attempt parallel mode even when not requested.

3. **Potential function visibility issue in GNU parallel branch**
   - `parallel ... process_account ...` relies on shell function availability in spawned jobs.
   - In many environments, spawned shells will not have `process_account` loaded, causing failures/no-op runs.

### Medium Priority
4. **JSON export assembly is fragile**
   - `json_results` entries are manually concatenated and separated via `sed` on `}{` boundaries.
   - Embedded braces/newlines from field data can produce invalid JSON.

5. **CSV export is unescaped**
   - Values are joined with commas directly.
   - Any comma, quote, or newline in real names, frameworks, or plugin output can corrupt CSV structure.

6. **Plugin loading trusts all `*.sh` files in plugin directory**
   - Every script is sourced into process context.
   - This is flexible but increases risk if `PLUGIN_DIR` is writable by untrusted users.

### Low Priority
7. **Potential portability assumptions**
   - Shebang is `#!/bin/zsh`; several commands assume macOS-specific tooling (`dscl`, `pwpolicy`, `stat -f`, `date -j`).
   - This is expected for stated target, but should be explicit in runtime checks and failure messaging.

## Recommended Next Actions
1. Wire UID range into scan filters so `-u` controls the actual account set processed.
2. Fix parallel gate and either:
   - properly export/load functions for parallel workers, or
   - disable parallel mode unless worker bootstrap succeeds.
3. Replace manual JSON/CSV generation with robust escaping/serialization.
4. Add a plugin trust model (owner/permission checks or allow-list).
5. Add shellcheck + basic fixture-driven smoke tests for parser/export behavior.
