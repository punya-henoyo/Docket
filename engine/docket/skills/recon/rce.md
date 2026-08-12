---
name: recon-rce
description: RCE testing covering command injection, deserialization, template injection, and code evaluation
---

# rce — for reconnaissance over source

You are READING SOURCE, not sending requests. Nothing below is a
step to perform against a running application; it is a description of where this class
of bug lives and what it looks like in code.

Use it to decide **where to read** and **what to compare**. The highest-value finding
in this class is usually an ABSENCE — a check that every sibling handler performs and
this one does not. You cannot grep for a line that was never written, so find it by
reading neighbours and noticing the disagreement.

Record what you find with `record_surface` as a candidate, citing file and line. A
candidate is a suspicion with evidence, never a proven vulnerability.

## Where this lives

**Command Execution**
- OS command execution via wrappers (shells, system utilities, CLIs)

**Dynamic Evaluation**
- Template engines, expression languages, eval/vm

**Deserialization**
- Insecure deserialization and gadget chains across languages

**Media Pipelines**
- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg

**SSRF Chains**
- Internal services exposing execution primitives (FastCGI, Redis)

**Container Escalation**
- App RCE to node/cluster compromise via Docker/Kubernetes

## Shapes this takes in code

### Command Injection

**Delimiters and Operators**
- Unix: `; | || & && `cmd` $(cmd) $() ${IFS}` newline/tab
- Windows: `& | || ^`

**Argument Injection**
- Inject flags/filenames into CLI arguments (e.g., `--output=/tmp/x`, `--config=`)
- Break out of quoted segments by alternating quotes and escapes
- Environment expansion: `$PATH`, `${HOME}`, command substitution
- Windows: `%TEMP%`, `!VAR!`, PowerShell `$(...)`

**Path and Builtin Confusion**
- Force absolute paths (`/usr/bin/id`) vs relying on PATH
- Use builtins or alternative tools (`printf`, `getent`) when `id` is filtered
- Use `sh -c` or `cmd /c` wrappers to reach the shell

**Evasion**
- Whitespace/IFS: `${IFS}`, `$'\t'`, `<`
- Token splitting: `w'h'o'a'm'i`, `w"h"o"a"m"i`
- Variable building: `a=i;b=d; $a$b`
- Base64 stagers: `echo payload | base64 -d | sh`
- PowerShell: `IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`

### Template Injection

Identify server-side template engines: Jinja2/Twig/Blade/Freemarker/Velocity/Thymeleaf/EJS/Handlebars/Pug

**Minimal Probes**
```
Jinja2: {{7*7}} → {{cycler.__init__.__globals__['os'].popen('id').read()}}
Twig: {{7*7}} → {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
Freemarker: ${7*7} → <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
EJS: <%= global.process.mainModule.require('child_process').execSync('id') %>
```

### Deserialization and EL

**Java**
- Gadget chains via CommonsCollections/BeanUtils/Spring
- Tools: ysoserial
- JNDI/LDAP chains (Log4Shell-style) when lookups are reachable

**.NET**
- BinaryFormatter/DataContractSerializer
- APIs accepting untrusted ViewState without MAC

**PHP**
- `unserialize()` and PHAR metadata
- Autoloaded gadget chains in frameworks and plugins

**Python/Ruby**
- pickle, `yaml.load`/`unsafe_load`, Marshal
- Auto-deserialization in message queues/caches

**Expression Languages**
- OGNL/SpEL/MVEL/EL reaching Runtime/ProcessBuilder/exec

### Media and Document Pipelines

**ImageMagick/GraphicsMagick**
- policy.xml may limit delegates; still test legacy vectors
```
push graphic-context
fill 'url(https://x.tld/a"|id>/tmp/o")'
pop graphic-context
```

**Ghostscript**
- PostScript in PDFs/PS: `%pipe%id` file operators

**ExifTool**
- Crafted metadata invoking external tools or library bugs

**LaTeX**
- `\write18`/`--shell-escape`, `\input` piping; pandoc filters

**ffmpeg**
- concat/protocol tricks mediated by compile-time flags

### SSRF to RCE

**FastCGI**
- `gopher://` to php-fpm (build FPM records to invoke system/exec)

**Redis**
- `gopher://` write cron/authorized_keys or webroot
- Module load when allowed

**Admin Interfaces**
- Jenkins script console, Spark UI, Jupyter kernels reachable internally

### Container and Kubernetes

**Docker**
- From app RCE, inspect `/.dockerenv`, `/proc/1/cgroup`
- Enumerate mounts and capabilities: `capsh --print`
- Abuses: mounted docker.sock, hostPath mounts, privileged containers
- Write to `/proc/sys/kernel/core_pattern` or mount host with `--privileged`

**Kubernetes**
- Steal service account token from `/var/run/secrets/kubernetes.io/serviceaccount`
- Query API for pods/secrets; enumerate RBAC
- Talk to kubelet on 10250/10255; exec into pods
- Escalate via privileged pods, hostPath mounts, or daemonsets

---

Adapted from the strix project's `skills/vulnerabilities/rce.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
