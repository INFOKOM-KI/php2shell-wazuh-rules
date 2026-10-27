# PHP2Shell detection rules for Wazuh

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/c4a08715-415b-4e38-a081-904161bb86c4" />

46 Wazuh rules for CVE-2026-109618 and CVE-2026-109619, the PHP
`session.upload_progress` flaws published on 2026-10-21. The rules cover the
request shapes the public exploit clients send, the PHP and kernel messages a
failed or successful exploitation leaves, the files the chain drops, and the
processes it spawns.

They detect effects. No log source reports the memory corruption itself, so a
single alert is a triage lead, not proof of RCE.

## Install

```bash
install -m 640 php2shell_rules.xml /var/ossec/etc/rules/php2shell_rules.xml
/var/ossec/bin/wazuh-control restart
```

Rules use 100701 to 100776. Renumber if your local set already uses that block.
Every rule carries `php2shell` plus one layer group: `php2shell_http`,
`php2shell_php`, `php2shell_crash`, `php2shell_persist`, `php2shell_body`,
`php2shell_recon`, `php2shell_exec`, or `php2shell_correlate`.

Rules 100720, 100721, and 100752 also carry `php2shell_crash_signal`, the group
100722 counts. Rules 100740, 100741, and 100743 carry `php2shell_arm`, the group
100753 and 100765 count. A counter stays out of the group it counts so it cannot
re-trigger on itself.

## Rules

### Access log

| ID | Level | Fires on |
|---|---|---|
| 100701 | 3 | HTTP 500 from a `.php` URL |
| 100702 | 10 | 5 of those from one IP in 120 s |
| 100703 | 4 | HTTP 503 from a `.php` URL |
| 100704 | 11 | 4 of those from one IP in 90 s |
| 100750 | 3 | GET of a PHP version or phpinfo page |
| 100751 | 6 | 10 missing `.php` paths from one IP in 120 s |
| 100761 | 10 | `auth_pass=` and `cmd=` of the dropped ZeroHack webshell |
| 100763 | 6 | HTTP 413/417 on a `.php` POST, an edge rejecting an oversized probe |
| 100765 | 14 | 5xx from an IP that sent a session-injection probe in the last 300 s (body log required) |
| 100767 | 10 | request path names a session file (`sess_<id>`), the LFI include step |
| 100770 | 5 | three or more `q\d{7}` query pairs, the 9bie transport marker |
| 100771 | 7 | HTTP 502 on a `.php` request, a FastCGI worker dying mid-request |
| 100775 | 10 | request path points at a web server log file, the log poisoning include |
| 100776 | 12 | PHP tag inside the closing header of an access log line |

Rules 100701, 100703, 100751, and 100765 depend on stock Wazuh rules 31101,
31120, 31122, and 31123, keyed on the decoded status code. The cross-source
correlations take `if_sid` for the current event and `if_matched_group` for the
earlier one, because `if_matched_sid` accepts a single rule ID.

### PHP runtime messages

| ID | Level | Fires on |
|---|---|---|
| 100710 | 8 | `Allowed memory size of ... bytes exhausted` |
| 100711 | 13 | 3 memory aborts in 180 s |
| 100712 | 12 | memory abort with `in Unknown on line`, the PoC probe response |
| 100713 | 8 | `Session ID is too long or contains illegal characters` |
| 100714 | 6 | `Failed to read session data` |
| 100754 | 10 | `Failed to decode session object` / `Session object destruction failed` |
| 100768 | 6 | `POST Content-Length of ... exceeds the limit of`, PHP dropped an oversized body |
| 100769 | 6 | `Multipart body parts limit exceeded` |

These match message text, not a parent decoder, so they fire on any log source
that carries the line.

### Crash and kernel

| ID | Level | Fires on |
|---|---|---|
| 100752 | 13 | `zend_mm_heap corrupted` |
| 100720 | 10 | `php-fpm`, `php-cgi`, `apache2` or `httpd` segfault |
| 100721 | 10 | OOM killer kills a PHP worker |
| 100722 | 14 | 5 worker deaths in 300 s |
| 100753 | 15 | corruption within 300 s of a session upload-progress arming probe |
| 100764 | 15 | corruption within 300 s of a persistence write |

### Filesystem and process

| ID | Level | Fires on |
|---|---|---|
| 100730 | 12 | `.htaccess` added or changed |
| 100731 | 12 | `.php` created under `/tmp` |
| 100755 | 8 | `.user.ini` added or changed |
| 100756 | 13 | webshell filename created (`pwn.php`, `shell.php`, `*.p2s*.php`, ...) |
| 100757 | 13 | web worker spawned a shell |
| 100758 | 13 | `/dev/tcp/`, `mkfifo`, or a Python socket in a command line |
| 100759 | 10 | web worker spawned `curl`, `wget`, `ncat`, or `socat` |

100757 to 100759 match any log that carries a full command line: auditd
`EXECVE` records, `journald`, or a Wazuh command monitor. They use lookaheads,
so field order inside the event does not matter.

### Request body and response markers

Body rules need ModSecurity audit logs, Suricata `eve.json` with
`http-body-printable`, or a proxy that logs bodies. 100760 also matches a logged
response. Plain access logs carry none of this, so these stay silent on
access-log-only deployments.

| ID | Level | Fires on |
|---|---|---|
| 100740 | 6 | `PHP_SESSION_UPLOAD_PROGRESS` field |
| 100741 | 10 | `PHPSESSID` sent as a multipart field instead of a cookie |
| 100742 | 13 | boundary `S` repeated 17 times (dimasma/eness clients) |
| 100743 | 13 | `<?php`, `%3C?php`, or `\|O:N:` inside a multipart filename |
| 100744 | 12 | `auto_prepend_file=` in a logged request |
| 100760 | 13 | `<<<P2S>>>` marker of the v2 webshell |
| 100762 | 10 | boundary `C` repeated 10 times or `----php2shellscanner` |
| 100766 | 12 | field name with a 10+ deep array chain (projectdiscovery OOM probe) |
| 100772 | 5 | `Transfer-Encoding: chunked`, the `post_max_size` bypass |
| 100773 | 8 | multipart filename over 400 bytes, session-file inflation |
| 100774 | 10 | `Set-Cookie: PHPSESSID=` starting with a non-session byte, heap leak |

## Log sources

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/php8.3-fpm.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>
```

FIM rules need the web root and the temp directories in `syscheck`:

```xml
<directories realtime="yes" report_changes="yes">/var/www</directories>
<directories realtime="yes">/tmp</directories>
```

## Verify

```bash
python3 check-rules.py
```

The script parses the XML, rejects duplicate IDs and out-of-range levels, checks
that every MITRE ID is well formed, compiles every regex, applies all text-only
rules to the sample lines, and rejects correlation options analysisd drops at
load. It fails if a rule matches no sample. It does not replace `wazuh-logtest`,
which also runs the decoder and the parent chain.

Patterns escape `/` as `\/`. Wazuh accepts either form; regex101 reads a bare
`/` as a delimiter and reports a pattern error.

For a live check, paste lines into `/var/ossec/bin/wazuh-logtest` from the file
that matches the stack:

| File | Stack |
|---|---|
| `logtest-samples-apache2.txt` | mod_php: `[php:warn]` error lines, `apache2[...]: segfault`, `(apache2)` OOM kill |
| `logtest-samples-nginx.txt` | php-fpm: `FastCGI sent in stderr`, `[pool www] child ... said into stderr`, `php-fpm8.2[...]` segfault, `(php-fpm8.2)` OOM kill |

Access-log lines use the combined format both servers emit by default.
Frequency rules (100702, 100704, 100711, 100722, 100751, 100753, 100764,
100765) need the parent line replayed several times inside the timeframe. FIM
rules cannot be tested with logtest; create and rename a throwaway `.php` file
under a monitored directory instead.

## Known limits

- A burst of 500s can be a broken deployment, a database outage, or a load
  test. 100702 and 100704 raise the level on count and timing, nothing more.
- One memory abort is normal in some applications. 100711 and 100712 are the
  ones worth paging on.
- `.htaccess` edits are routine on shared hosting and in CMS update flows.
  Expect a tuning pass on 100730.
- 100742 matched a benign upload with the same 17-`S` boundary in the dimasma
  lab run. Treat the boundary rules as fingerprints, not verdicts.
- Boundaries change per run in most clients. 100740, 100741, 100743, and 100766
  survive that; the boundary rules do not.
- 100753, 100764, and 100765 correlate across log sources. If one side is not
  collected, the correlation rule never fires.
- PHP 8.1 and older are EOL and get no upstream patch, so turn off
  `session.upload_progress` on those hosts.

## Technique to rule map

`techniques.md` lists every exploit type found in the eleven source
repositories and the rule that covers it.

## References

- PHP advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp
- Fixed releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12
- Interim mitigation: `session.upload_progress.enabled = Off`
