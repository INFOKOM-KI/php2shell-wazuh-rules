# PHP2Shell detection rules for Wazuh

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/c4a08715-415b-4e38-a081-904161bb86c4" />

63 Wazuh rules for CVE-2026-109618 and CVE-2026-109619, the PHP
`session.upload_progress` flaws published on 2026-10-21. The set also covers
the related CVE-2026-115560 serialize-handler mismatch.

The rules cover the request shapes the public exploit clients send, the PHP
and kernel messages a failed or successful exploitation leaves, the files the
chain drops, the processes it spawns, and the stage pairs that separate a probe
from a compromise. `techniques.md` maps each exploit type to the rule that
covers it.

They detect effects. No log source reports the memory corruption itself, so a
single alert is a triage lead, not proof of RCE.

## Install

```bash
install -o root -g wazuh -m 640 existing_rules.xml \
  /var/ossec/etc/rules/php2shell_rules.xml
/var/ossec/bin/wazuh-control restart
```

`analysisd` runs as user `wazuh`. A file owned `root:root` with mode 640 is
skipped at load and the rules stay silent, so keep the `-g wazuh`. Check for
`(1103): Could not open file` in `/var/ossec/logs/ossec.log` after the restart.

Rules use IDs 111000 to 111153. Renumber if your local set already uses that
block.

## Dependencies

The rules use stock syscheck parents and host ruleset parents. Install the host
ruleset first.

### Parent rules

| Parent | Line it scopes |
|---|---|
| 31100, 31530 | web access log, and POST on it |
| 31410, 31420 | PHP Warning, PHP Fatal error |
| 30301, 30302 | Apache error, Apache warn |
| 31300, 31301 | nginx grouped messages, nginx error |
| 550, 554 | syscheck checksum change, file added |
| 100009, 101900 | the host's ModSecurity base rule and the severity-2 rule on it |

111003 lists both ModSecurity parents because 101900 compares `severity` against
the literal `^2$`, so one parent could leave the rule silent.

### Anchors

Four anchors replace a parent where no single rule owns the log line:

| Anchor | Rules | Line it scopes |
|---|---|---|
| `if_group audit_command` | 3 | auditd process records |
| `decoded_as auditd` | 1 | audit records outside the command group |
| `if_group modsecurity` | 16 | request bodies a ModSecurity rule matched |
| `program_name kernel` | 2 | kernel messages, tagged by the syslog decoder |

### Load behavior

A missing `if_sid`, `if_group` or `decoded_as` is fatal at load: analysisd drops
the rule and logs which one. `program_name` and body-group membership are not
fatal that way. A kernel line without the tag, or a body line that matched no
ModSecurity rule, leaves the rule loaded and quiet, so a clean log does not prove
these are working.

After a restart:

```bash
grep -E "\(761[79]\)|Signature ID" /var/ossec/logs/ossec.log
```

Each line names a rule and the ID it could not resolve. A clean load prints
nothing.

Rules load in file order, and `if_matched_sid` only resolves upward. The counter
111106 therefore sits below 111107, the rule it counts.

### Visibility trade-offs

Parent choice sets what a rule can see. A narrow or mismatched parent can
silence a rule.

- 111011 fires on POST only, because 31530 is the POST access-log rule.
- 111001 could not fire. It tested a URL while carrying `if_sid 31410`, the
  PHP Warning rule, and no event is both. It now sits on 31100.
- The PHP message rules list `31300` beside the Apache PHP parents, so mod_php
  error logs and php-fpm stderr through nginx both reach them. 111013 does the
  same with 31300, 30301 and 30302.

## Rule groups

Every rule carries `php2shell` and `php2shell_exploit` from the file header,
plus one or more layer groups:

| Group | Rules | Scope |
|---|---|---|
| `php2shell_http` | 15 | access log |
| `php2shell_body` | 18 | request body |
| `php2shell_php` | 9 | PHP runtime messages |
| `php2shell_arm` | 11 | probe shapes the chain rules count |
| `php2shell_persist` | 12 | dropped files, `auto_prepend_file`, webshell markers |
| `php2shell_recon` | 4 | probing and enumeration |
| `php2shell_crash` | 4 | worker deaths |
| `php2shell_crash_signal` | 3 | the crash events 111116 counts |
| `php2shell_correlate` | 3 | staged chains |
| `php2shell_exec` | 4 | process execution, `/proc/<pid>/mem` writes |
| `php2shell_oom` | 2 | the abort events 111143 counts |

A counter that uses `if_matched_group` never carries the group it counts, so it cannot re-trigger on itself.

## Severity bands

| Band | Meaning | Examples |
|---|---|---|
| 3 to 4 | Recon or a single generic failure | phpinfo probing, one 500, unwritable save path |
| 5 to 8 | One indicator of the exploit path | transport marker, chunked body, part-flood, boundary string |
| 10 to 13 | One strong indicator | session file include, `auto_prepend_file`, shell spawn, `<<<P2S>>>` |
| 14 to 15 | Two stages seen together | crash after arming probes, crash after persistence writes |

The bands follow evidence strength. An oversized upload or a generic PHP error
sits low on purpose: both are routine on healthy deployments.

## Detection stages

| Stage | Rules |
|---|---|
| Request shape, access log | 111001, 111104, 111108 |
| Request shape, body | 111121 to 111124, 111126 to 111129, 111144, 111145, 111150, 111152, 111153 |
| Session and heap effects | 111002, 111009, 111010, 111012, 111112, 111130, 111143 |
| Worker failure | 111011, 111013, 111099, 111101 to 111103, 111114 to 111116 |
| Persistence | 111117 to 111120, 111125, 111134, 111147, 111148, 111149, 111151, 111152 |
| Post-exploitation | 111109, 111110, 111111, 111131 to 111133, 111146, 111147, 111149 |
| Staged chains | 111100, 111141, 111142 |

The chains need a current event plus earlier events from a named group:

- 111100: crash or shell spawn after 2 arming events in 600 s
- 111141: crash after 2 persistence writes in 300 s
- 111142: 5xx from the same source that sent 2 arming events in 300 s

Kernel and FIM events carry no source IP, so 111100 and 111141 are host scope.
Among the chain rules, only 111142 compares `srcip`.

## Rule overlaps

| Pair or rule | Overlap | Handling |
|---|---|---|
| 111111 and 111151 | The same `auth_pass` and `cmd` pair can appear in a URL or a POST body | Different log sources; one alert per event |
| 111111 and 111147 | A webshell request with parameters matches the query pair and the path | 111111 is ordered first; 111147 covers the path-only case |
| 111131 and 111132 | A reverse shell can match the shell-spawn rule and the `/dev/tcp` rule | 111132 is ordered first; a plain shell reports 111131 |
| Specific rules and 111121 | The generic progress rule can match almost every exploit body | Body rules are ordered specific to generic; recheck order after edits |
| 111123 and 111126 | Both match fixed boundary strings; 111123 has a known benign match from the dimasma lab | Kept separate so the noisy string stays at its own level |
| 111002 and 111112 | Both match a memory-limit abort, separated by a lookahead for the source location | Mutually exclusive |
| 111118, 111120, and 111149 | Webshell files, executable PHP files in `/tmp`, and output files overlap in some cases | Different file classes and levels |
| 111144, 111150, 111126 | These match fixed strings from public clients | Strong when they match, silent when a client changes the strings |

## Log sources

### Access and runtime logs

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

### Request bodies

Body rules need ModSecurity audit logs, Suricata `eve.json` with
`http-body-printable`, or a proxy that logs bodies. Plain access logs carry no
body, so those rules stay silent.

### FIM scope

```xml
<directories realtime="yes" report_changes="yes">/var/www</directories>
<directories realtime="yes">/tmp</directories>
```

Kernel, auditd and FIM rules stay silent without their sources. A missing source
means no alert, not a failure.

## Verify

```bash
python3 check-rules.py existing_rules.xml
```

The default rules file is `existing_rules.xml`. Pass another path to check a
different file.

The script parses the XML, rejects duplicate IDs and out-of-range levels, checks
that every MITRE ID is well formed, compiles every regex, and applies all
text-only rules to the sample lines. It fails if a rule matches no sample.

It does not replace `wazuh-logtest`, which also runs the decoder and the parent
chain. The script also ignores rule order and parent groups, so one sample line
can list several rules that cannot fire on the same event. analysisd applies the
first matching rule among siblings, and the file orders specific rules before
generic ones.

Patterns escape `/` as `\/`, and XML text escapes `&` as `&amp;`. The second is
not optional: one raw `&` stops the file from parsing.

| File | Contents |
|---|---|
| `logtest-samples-apache2.txt` | mod_php: `[php:warn]` error lines, ModSecurity audit lines, `apache2[...]: segfault`, `(apache2)` OOM kill, access log |
| `logtest-samples-nginx.txt` | php-fpm: `FastCGI sent in stderr`, `[pool www] child ... said into stderr`, `php-fpm8.2[...]` segfault, `(php-fpm8.2)` OOM kill, access log |
| `logtest-benign-apache2.txt` | normal traffic, one 404, a 16-`S` boundary, a session cookie with a normal value |
| `logtest-benign-nginx.txt` | the same shapes on the nginx stack |

Frequency rules (111099, 111103, 111106, 111116, 111143) need the parent line
replayed several times inside the timeframe. The chain rules need events from
two groups. FIM rules cannot be tested with logtest; create and rename a
throwaway `.php` file under a monitored directory instead.

## Known limits

### Rule behavior

- A burst of 500s can be a broken deployment, a database outage, or a load
  test. 111099 raises the level on count and timing, nothing more.
- One memory abort is normal in some applications. 111112 and 111143 are the
  ones worth paging on.
- Boundaries change per run in most clients. 111121, 111122, 111124, 111144,
  111145, 111150 and 111152 survive that; the fixed boundary rules do not.
- 111132 and 111133 are ordered before 111131, so a reverse shell or a network
  fetch reports the more specific rule. A plain shell spawn reports 111131.

### Log-source gaps

- 111131 and 111133 require an execution record (`EXECVE`, `execve(`, `exe="`
  or `COMMAND=`). The Elastic APM tracer line does not match: it prints a
  libcurl version block and its own `php-fpm: pool` name together.
- Under php-fpm, auditd records the executed binary, so a shell started by a
  pool child shows `exe="/bin/sh"` or `exe="/usr/bin/curl"`. The pool name
  is absent and 111131 and 111133 stay quiet. mod_php is covered, because
  `exe="/usr/sbin/apache2"` sits on the record.
- 111144 to 111153 report only when their source is collected. The body,
  access-log, FIM and auditd rules stay silent otherwise.
- 111146 only fires when auditd records an open or write against
  `/proc/<pid>/mem`. A host without that audit watch keeps the rule quiet.
- A passive version check reads `X-Powered-By` or sends a plain `HEAD /`. That
  leaves no request signature beyond normal traffic. 111105 catches an exposed
  `phpinfo` page, not a header-only check.
- Raw FastCGI to FPM, the syrex direct path, bypasses the web access log. The
  request-shape rules stay silent unless a network sensor, an FPM request log,
  or an auditd watch supplies the event. A blind timing oracle has the same
  problem until the command reaches auditd.
- Body rules see only lines a ModSecurity rule matched. Pair them with a
  body-logging proxy or a network sensor.
- FIM rules see only directories in the syscheck scope. Add the web root and the
  temp directories. A webshell dropped outside a monitored directory produces
  no alert.
- Correlating across sources produces no alert when one side is not collected.
  If only the access log is shipped, the arming group still fills through
  111001, 111004, 111104 and 111108.

### Tuning

- `.htaccess` edits are routine on shared hosting and in CMS update flows.
  Expect a tuning pass on 111117.
- A 17-`S` boundary matched a benign upload in the dimasma lab run. Treat the
  boundary rules (111123, 111126) as supporting evidence. 111126 also matches
  a boundary of exactly ten `B` or `C` characters, which a benign client could
  pick by chance.
- An oversized multipart filename (111129) and a chunked body (111128) are
  common in healthy APIs. They sit at 8 and 5 for that reason.
- 111130 treats a PHPSESSID value of 64 characters or more as a leak. An
  application that issues its own long session ids raises it. The non-session
  byte and percent-encoded forms are the stronger signals.
- 111149 watches for `p1`, `pwn.txt`, `leakfile` and `.p2s_*` output files. A
  benign job that writes one of those names under `/tmp` or `/out` raises it;
  the level stays at 8 for that reason.

### Deployment

- PHP 8.1 and older are EOL and get no upstream patch, so turn off
  `session.upload_progress` on those hosts.

## Related documents

- `techniques.md` maps each exploit type and client chain to the rule that
  covers it.
- `check-rules.py` runs the offline checks described above.

## References

- PHP advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
  [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- Fixed releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12
- Interim mitigation: `session.upload_progress.enabled = Off`
