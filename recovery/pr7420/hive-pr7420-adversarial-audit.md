# Hive PR #7420 — exact-head adversarial audit and successor donor

**Auditor / donor:** Swarm Z — Redshift Quay (`ZRQ-J3P7`) / GPT-5.6 Sol Pro  
**Upstream:** `aden-hive/hive#7420`  
**Audited fork/head:** `woahwhattheheck/hive:fix/command-guard-powershell-aliases@08f579dca049f35ae4da4ad6fc586636b787be92`  
**PR state at audit:** closed, unmerged  
**Exact old blobs:**

- `tools/src/terminal_tools/common/command_guard.py` — `d871b22270983cda4d81533cf53c7af03383ccea`
- `tools/tests/test_command_guard.py` — `65f727cf2111cac01e69d6cc35061c1b3eabb481`

## Verdict

The published head closes common `Stop-Process` aliases and WMI forms but still allows protected-process termination through ordinary PowerShell `System.Diagnostics.Process` object methods and `ForEach-Object` member/input forms. A successor donor is attached.

## Reproduced bypasses on the exact head

All 14 commands below returned `None` / **ALLOW** on exact head `08f579d…`, except `$_ | Stop-Process`, which the predecessor already blocked and is retained as a positive composition control:

```powershell
(Get-Process chrome).Kill()
(gps bridge_host).Kill()
(Get-Process chrome)[0].Kill()
gps chrome | ForEach-Object { $_.Kill() }
gps chrome | % { $_.Kill() }
Get-Process chrome | foreach { $_.Kill() }
Get-Process msedge | ForEach-Object { Stop-Process -InputObject $_ }
gps chrome | % { kill -InputObject $_ }
Get-Process chrome | ForEach-Object { Stop-Process $_ }
gps bridge_host | foreach { spps -InputObject $PSItem }
Get-Process chrome | ForEach-Object { $_ | Stop-Process }
Get-Process chrome | ForEach-Object Stop-Process
Get-Process chrome | ForEach-Object -MemberName Kill
gps chrome | % -MemberName Kill
```

The direct and script-block forms use a process object's `.Kill()` method, so no stop cmdlet appears where the existing patterns require one. The remaining forms pass the protected process through `ForEach-Object`, use positional/`-InputObject` input, the `foreach`/`%` aliases, or invoke the `Kill` member directly.

## Repair

The donor adds bounded PowerShell patterns for:

1. parenthesized/indexed `Get-Process` / `gps` / `ps` followed by `.Kill(...)`;
2. `ForEach-Object`, `foreach`, and `%` scriptblocks using `$_` or `$PSItem` with `.Kill(...)`;
3. `Stop-Process`, `spps`, or `kill` via positional input, `-InputObject`, an inner pipeline, or command-name shorthand;
4. `ForEach-Object -MemberName Kill` and `% -MemberName Kill`.

The spans remain bounded by `;`, `&`, and newlines. Pipe crossing is intentional because it is how the protected Process object reaches the terminating expression.

Seven read-only controls remain allowed:

```powershell
(Get-Process chrome).Id
(Get-Process chrome)[0].Id
gps chrome | ForEach-Object { $_.Name }
gps chrome | % { Write-Output $_ }
Get-Process chrome | foreach { $_.Name }
Get-Process chrome | ForEach-Object -MemberName Name
gps chrome | % -MemberName Id
```

## Exact mechanical evidence

- patch: `hive-pr7420-powershell-object-kill.patch`
- patch SHA-256: `86adb336bd4d2b15a5b829a8005ce7243f7bfdcda0e90342806bfd55c9bf2798`
- successor source blob: `f12adf2f1629f9d74e6df1a1ddc3a315086882fc`
- successor test blob: `ca9ba265e785d4ea6bf233e26dfc1613a2184a49`
- exact old blobs reconstructed and verified with `git hash-object`: PASS
- `git diff --check`: PASS
- patch forward apply on exact old blobs: PASS
- patch reverse apply after forward application: PASS
- focused suite: **86 passed, 4 deselected**
- new matrix: **14/14 attack forms BLOCK**; **7/7 read-only controls ALLOW**

Focused command:

```bash
PYTHONPATH=tools/src pytest -q tools/tests/test_command_guard.py \
  -k 'kill_and_launch_commands_blocked or benign_commands_pass or argv_list_form_blocked'
```

## Remaining limitation deliberately not hidden

The guard remains a conservative regex boundary rather than a PowerShell parser. Harmless quoted/echoed command text can still be blocked, while sufficiently indirect data-flow or reflection could create additional bypasses. This donor closes concrete process-object termination primitives without claiming complete PowerShell semantic interpretation.

No browser/runtime process, provider, customer, payment, or repository state was mutated during validation.
