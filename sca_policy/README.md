# PHP2Shell SCA policies

Two Linux SCA policies for hosts that run PHP. They check the runtime settings
and host controls that the PHP2Shell chains depend on. They do not replace the
Wazuh detection rules in `existing_rules.xml`.

## Files

| File | Policy ID | Checks |
|---|---|---|
| `sca_php2shell_php_runtime.yml` | `php2shell_php_runtime` | 11 |
| `sca_php2shell_web_server.yml` | `php2shell_web_server` | 7 |

### PHP runtime checks

| ID | Check |
|---|---|
| 42000 | PHP is at or above the fixed release for its branch |
| 42001 | `session.upload_progress.enabled` is off |
| 42002 | `session.upload_progress.cleanup` is on |
| 42003 | `session.use_strict_mode` is on |
| 42004 | `session.use_only_cookies` is on |
| 42005 | `expose_php` is off |
| 42006 | `display_errors` is off |
| 42007 | `post_max_size` is 32 MiB or less |
| 42008 | `allow_url_include` is off |
| 42009 | `session.save_path` is outside the web root |
| 42010 | `max_multipart_body_parts` is 1000 or less, where supported |

### Web server checks

| ID | Check |
|---|---|
| 42100 | `auditd` is running |
| 42101 | The audit rules record `execve` |
| 42102 | Common web roots have no world-writable PHP files |
| 42103 | Temporary directories have no executable PHP files |
| 42104 | Session files are not world-readable |
| 42105 | ModSecurity sets `SecRuleEngine` to `On` |
| 42106 | Web directories have no PHP2Shell overrides |

## Install

### Push from the manager

1. Copy both YAML files to `/var/ossec/etc/shared/default/` on the manager and set ownership:

   ```bash
   install -o wazuh -g wazuh -m 660 sca_php2shell_*.yml /var/ossec/etc/shared/default/
   ```

2. Allow SCA commands from the manager on each agent:

   ```bash
   echo "sca.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
   ```

   This lets the manager run commands on the endpoint. Enable it only for agents in the group that receive these policies.

3. Add the policies to `/var/ossec/etc/shared/default/agent.conf`:

   ```xml
   <agent_config>
     <sca>
       <policies>
         <policy>etc/shared/sca_php2shell_php_runtime.yml</policy>
         <policy>etc/shared/sca_php2shell_web_server.yml</policy>
       </policies>
     </sca>
   </agent_config>
   ```

4. Restart the agent:

   ```bash
   systemctl restart wazuh-agent
   ```

SCA rescans a policy when its file hash changes and sends a result for every check in that policy.

### Manual install

Copy the files to `/var/ossec/ruleset/sca/` on each agent. Updates do not
preserve that directory. For a path outside the ruleset, add an absolute path to
the agent `<sca>` block.

## PHP in Docker containers

`sca_php2shell_docker_runtime.yml` repeats the runtime checks inside every
running container. A host that runs PHP in both places needs the host policy
and this one.

The policy asks Docker for the container IDs, then runs PHP in each container:

```bash
docker ps --quiet
docker exec <container> php -v
docker exec <container> php -i
```

SCA runs with no terminal and no stdin. `docker exec -it` fails there with "the
input device is not a TTY", so the policy leaves out `-it` and calls PHP
directly. That also covers images with no shell, and avoids a quoting layer.
Keep `-it` for the interactive shell:

```bash
docker ps --format '{{.ID}}  {{.Names}}  {{.Image}}'
container=$(docker ps --quiet | head -1)
docker exec -it "$container" /bin/bash
docker exec -it "$container" /bin/sh   # image without bash
docker exec "$container" php -v
docker exec "$container" php -i | grep -E 'session.upload_progress|session.use_strict_mode|expose_php'
```

Check 42200 fails when the agent cannot reach the Docker daemon. Check 42201
fails when no running container has a PHP CLI. Without 42201, an empty container
set would pass every later check.

Every later check runs its command in all containers and fails when any
container reports a bad value. One check covers all containers, so a failure
names the directive but not the container that set it. When you need that link,
use one copy of the policy per container. Give the copy its own
`id`, its own check IDs (they must be unique across the agent), and a
`$containers` value of `echo <container>`.

Make those copies on the agent. `docker ps` on the manager lists the manager's
containers, not the agent's. Keep the copies outside `ruleset/sca`, because an
agent update replaces that directory.

Each check costs one `docker exec` per container. The default
`sca.commands_timeout` is 30 seconds. Raise it on hosts with many containers:

```bash
echo "sca.commands_timeout=120" >> /var/ossec/etc/local_internal_options.conf
```

The agent user needs access to the Docker socket. The agent runs as root by
default, so it has access.

A new container appears in the results on the next scan. The default interval
is 12 hours. Restart the agent after a deploy to scan at once. Editing the
policy file also triggers a full rescan, and every check in that policy reports
again.

Use the fixed release for the branch you run. For PHP 8.2, that is 8.2.35.
Rebuild the image on a fixed tag. Do not patch only the running container.

The web server policy still checks host-level controls such as auditd and
ModSecurity. It does not inspect container file systems.

## Limits

- The PHP checks read the CLI SAPI. Confirm that the FPM pool or Apache vhost
  uses the same `php.ini`, or repeat the checks against the web SAPI configuration.
- Per-vhost `.htaccess` and `.user.ini` overrides can change these values for the web SAPI. Check the vhost configuration as well.
- The patch check reads `PHP_VERSION`. A distro backport can keep the upstream
  version string, so confirm the vendor advisory for the package.
- Check 42001 assumes upload progress is not needed. If a patched application uses it, record an exception and rely on the patch.
- The ModSecurity check fails on hosts that use a network WAF or another local WAF. Treat it as not applicable there.
- Checks 42102 to 42104 and 42106 scan common paths only. Change the paths if the web root or session save path is different.
- A passing SCA scan does not prove the host is unexposed. The detection rules and the patch level check still matter.

## References

- https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html
- https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-to-configure.html
- https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html
