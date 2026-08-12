"""Builds SDK Agent objects: LiteLLM model wiring, per-role tool list, and the
tool_use_behavior gate that stops the loop only via a dedicated finish tool.

Root's coordination tools (create_agent/wait_for_agents/view_agent_graph, in
graph_tools.py) are NOT imported here — graph_tools.py imports build_agent (to
construct the children it spawns), so importing it back here would cycle. The caller
(scan.py) passes those tools in via extra_tools instead.
"""
from __future__ import annotations

import asyncio
from typing import Any, Literal

from agents import Agent, FunctionToolResult, RunContextWrapper, Tool, ToolsToFinalOutputResult, function_tool
from agents.extensions.models.litellm_model import LitellmModel
from agents.models.interface import Model
from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Filesystem, Shell

from docket.config.settings import Config
from docket.core.execution import ScanContext
from docket.core.inputs import build_model_settings
from docket.interface.tui.backend.messages import get_emitter
from docket.tools.finish.tool import agent_finish, finish_scan
from docket.agents.prompts.root import SYSTEM_PROMPT as ROOT_SYSTEM_PROMPT
from docket.agents.prompts.specialist import SYSTEM_PROMPT as SPECIALIST_SYSTEM_PROMPT
from docket.agents.prompts.recon import SYSTEM_PROMPT as RECON_SYSTEM_PROMPT
from docket.agents.prompts.triage import SYSTEM_PROMPT as TRIAGE_SYSTEM_PROMPT
from docket.tools.recon.tool import record_surface
from docket.tools.source.tools import list_source, read_source, search_source
from docket.tools.triage.tool import triage_verdict
from docket.tools.load_skill.tool import list_skills, load_skill
from docket.tools.notes.tools import add_note, view_notes
from docket.tools.reporting.tool import FindingType, register_finding
from docket.tools.respond.tool import respond as respond_impl
from docket.tools.thinking.tool import think
from docket.tools.todo.tools import set_todos, view_todos
from docket.tools.web_search.tool import web_search
from docket.tools.http_request.tools import do_http_request

Role = Literal["root", "sqli", "cmdi", "xss", "triage", "recon"]
SpecialistRole = Literal["sqli", "cmdi", "xss"]

_FINISH_TOOL_NAMES = {"finish_scan", "agent_finish", "triage_verdict", "record_surface"}


@function_tool(strict_mode=False)  # headers/params/data are open-ended dicts — strict
# JSON schema mode can't represent those (it requires enumerated properties).
async def http_request(
    ctx: RunContextWrapper[ScanContext],
    method: str,
    url: str,
    headers: dict | None = None,
    params: dict | None = None,
    data: dict | None = None,
    timeout_sec: int = 15,
) -> dict:
    """Send a raw HTTP request to the target and return status/headers/body/timing.
    `data` as an object is form-urlencoded, matching how Flask reads request.form."""
    # Both branches are synchronous and blocking, so both go off-thread: one agent's
    # blocking call (e.g. the deliberate 3s timing probe for blind command injection)
    # must not freeze the event loop for every other concurrently running agent.
    # Without this, "multi-agent" would be multi-agent in name only.
    sandbox = ctx.context.sandbox
    if sandbox is not None:
        return await asyncio.to_thread(
            sandbox.call, "http_request", method=method, url=url,
            headers=headers, params=params, data=data, timeout_sec=timeout_sec,
        )
    return await asyncio.to_thread(
        do_http_request, method, url, ctx.context.run_dir,
        headers=headers, params=params, data=data, timeout_sec=timeout_sec,
    )


def supports_hosted_tools(model: Model | None) -> bool:
    """Can this model carry the SDK's HOSTED tools (apply_patch, view_image, the
    native sandbox shell)?

    Only over OpenAI's Responses API. Every LiteLLM-routed model — which is docket's
    whole point, including its own documented default anthropic/claude-sonnet-5 —
    speaks ChatCompletions, where the SDK raises

        UserError: Hosted tools are not supported with the ChatCompletions API.
                   Got tool type: SandboxApplyPatchTool

    before the first turn even runs. Found by the first live-model run: every
    sandboxed scan with a real model died here instantly, while the scripted test
    model sailed past because it never goes through LiteLLM's tool serialisation.
    That is exactly the gap the README's "not yet verified with a live model" was
    hiding.

    Dropping to a plain Agent costs nothing docket uses: `shell` and `browser` are
    docket's own function tools that reach the container over the RPC shim, and it
    narrows the blast radius the README flags as its own least-privilege gap.
    """
    return not isinstance(model, LitellmModel)


@function_tool
async def shell(
    ctx: RunContextWrapper[ScanContext],
    command: str,
    timeout_sec: int = 30,
) -> dict:
    """Run a shell command inside the sandbox container. Security tooling is
    pre-installed — notably sqlmap at /opt/sqlmap/sqlmap.py. Returns exit code,
    stdout, stderr and duration."""
    sandbox = ctx.context.sandbox
    if sandbox is None:
        # Hard refusal, not a fallback. An LLM-authored shell command belongs in the
        # container or nowhere; silently running it on the operator's own machine
        # would defeat the entire point of having a sandbox.
        return {
            "error": "no sandbox available — shell commands are never executed on the "
            "host. Re-run the scan with the Docker sandbox enabled.",
            "exit_code": None,
        }
    return await asyncio.to_thread(sandbox.call, "shell", command=command, timeout_sec=timeout_sec)


@function_tool
async def browser(
    ctx: RunContextWrapper[ScanContext],
    action: Literal["navigate", "click", "fill", "get_text", "get_html", "evaluate", "wait_for", "screenshot", "close"],
    url: str | None = None,
    selector: str | None = None,
    text: str | None = None,
    script: str | None = None,
    timeout_sec: int = 10,
) -> dict:
    """Drive a real Chromium page in the sandbox. Key field in the result:
    `dialog_message` — if the page raised an alert/confirm/prompt during this action it
    appears here, which is direct proof a script EXECUTED rather than merely being
    echoed into the HTML. Use `screenshot` to save visual evidence."""
    sandbox = ctx.context.sandbox
    if sandbox is None:
        return {"ok": False, "error": "no sandbox available — the browser runs only inside the container."}
    return await asyncio.to_thread(
        sandbox.call, "browser", action=action, url=url, selector=selector,
        text=text, script=script, timeout_sec=timeout_sec,
    )


@function_tool(strict_mode=False)  # location/poc are open-ended dicts, same reason
async def finding(
    ctx: RunContextWrapper[ScanContext],
    rule_type: FindingType,
    severity: Literal["critical", "high", "medium", "low", "info"],
    title: str,
    description: str,
    location: dict,
    poc: dict,
) -> dict:
    """Register a CONFIRMED vulnerability. poc.request and poc.response_excerpt must
    contain real, reproduced evidence you actually observed — never call this on a
    hunch or before you've tried the exploit."""
    result = register_finding(
        rule_type=rule_type, severity=severity, title=title, description=description,
        location=location, poc=poc, discovered_by=ctx.context.role,
        run_dir=ctx.context.run_dir, on_finding=ctx.context.on_finding,
    )
    # Emitted here rather than from the generic tool hook: only this wrapper has the
    # finding's real fields. The hook only sees the return value, which is just an ID —
    # emitting that would make every finding render as severity "info".
    # Normalise the location the same way register_finding does: agents pass a full
    # `url`, while the UI (and the report) key off method/path/parameter.
    from urllib.parse import urlparse

    get_emitter().finding(
        ctx.context.agent_id, ctx.context.role,
        finding_id=result.get("finding_id"), rule_type=rule_type, severity=severity,
        title=title,
        location={
            "method": location.get("method", "GET"),
            "path": urlparse(location.get("url", "")).path or location.get("path", ""),
            "parameter": location.get("parameter"),
        },
    )
    return result


@function_tool
async def thinking(ctx: RunContextWrapper[ScanContext], thought: str) -> dict:
    """Record your reasoning before acting. Use it to plan which payload to try and
    why. It performs no action — its value is that the reasoning behind a choice ends
    up in the transcript where a human reviewer can see it."""
    return think(thought)


@function_tool
async def notes(
    ctx: RunContextWrapper[ScanContext],
    action: Literal["add", "view"],
    text: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Shared scratchpad across ALL agents in this scan. Record facts another
    specialist would otherwise rediscover (how the app signals success/failure, a
    working payload shape, a dead end). `view` reads everyone's notes."""
    run_dir = ctx.context.run_dir
    if action == "add":
        if not text:
            return {"ok": False, "error": "add requires `text`"}
        return add_note(run_dir, text, tags, author=ctx.context.role)
    return view_notes(run_dir, tag=(tags[0] if tags else None))


@function_tool(strict_mode=False)  # items is a list of open-ended dicts
async def todo(
    ctx: RunContextWrapper[ScanContext],
    action: Literal["set", "view"],
    items: list[dict] | None = None,
) -> dict:
    """Your own task list for this investigation. `set` replaces the whole list —
    send every item each time, with status pending|in_progress|done."""
    run_dir = ctx.context.run_dir
    if action == "set":
        return set_todos(run_dir, items or [], agent_id=ctx.context.agent_id)
    return view_todos(run_dir, agent_id=ctx.context.agent_id)


@function_tool
async def respond(ctx: RunContextWrapper[ScanContext], message: str) -> dict:
    """Send a message to the human operator. In a non-interactive run it is recorded
    to the run directory and shown in the report rather than dropped."""
    return respond_impl(ctx.context.run_dir, message, agent_id=ctx.context.agent_id)


@function_tool(name_override="load_skill")
async def load_skill_tool(ctx: RunContextWrapper[ScanContext], name: str) -> dict:
    """Load a playbook into context by name (e.g. "custom/blind_injection"). Call
    list_skills first if unsure. Loading on demand keeps unrelated playbooks out of
    your context."""
    return load_skill(name)


@function_tool(name_override="list_skills")
async def list_skills_tool(ctx: RunContextWrapper[ScanContext]) -> dict:
    """List the playbooks available to load_skill."""
    return list_skills()


@function_tool(name_override="web_search")
async def web_search_tool(
    ctx: RunContextWrapper[ScanContext], query: str, max_results: int = 5,
) -> dict:
    """Search the web for real-time intel (a CVE, a framework's known weak spot, a
    payload technique). Returns an explicit error if no search provider is configured
    — in that case work from what you can observe on the target."""
    return await asyncio.to_thread(web_search, query, max_results)


# Agent utilities every role gets: reasoning, shared memory, task tracking, and the
# ability to pull in a playbook. None of them touch the target, so there's no reason
# to withhold any of them from a specialist.
_COMMON_TOOLS: list[Tool] = [thinking, notes, todo, load_skill_tool, list_skills_tool, web_search_tool]


async def _finish_tool_use_behavior(
    ctx: RunContextWrapper[ScanContext], results: list[FunctionToolResult],
) -> ToolsToFinalOutputResult:
    """The loop only ends when the model calls a dedicated finish tool — enforced
    structurally here, not by asking nicely in the prompt."""
    last = results[-1]
    if last.tool.name in _FINISH_TOOL_NAMES and isinstance(last.output, dict):
        # Park it on the context too. Without Agent.output_type the SDK stringifies
        # whatever it gets here, so this is the only lossless channel back to
        # run_agent_loop — see ScanContext.final_result.
        ctx.context.final_result = last.output
        return ToolsToFinalOutputResult(is_final_output=True, final_output=last.output)
    return ToolsToFinalOutputResult(is_final_output=False, final_output=None)


def build_agent(
    role: Role,
    config: Config,
    *,
    extra_tools: list[Tool] | None = None,
    model: Model | None = None,
    sandbox: Any | None = None,
) -> Agent[ScanContext]:
    """`model`, if given, overrides the real LitellmModel — used by tests to script a
    child agent's decisions (see ScanContext.model_override in core/execution.py).

    `sandbox`, if given, builds a SandboxAgent with the SDK's native Filesystem and
    Shell capabilities bound to that container, instead of a plain Agent. That is what makes apply_patch and view_image work
    without custom implementations — they come from the SDK, pointed at our sandbox.
    ONLY when the model can actually carry hosted tools; see supports_hosted_tools.
    """
    if role == "root":
        instructions = ROOT_SYSTEM_PROMPT
        finish_tool = finish_scan
        name = "docket-root"
        # Root delegates, so it gets no `finding`; it does get `respond`, being the
        # agent that speaks for the scan.
        base_tools: list[Tool] = [http_request, respond, *_COMMON_TOOLS]
    elif role in ("sqli", "cmdi", "xss"):
        instructions = SPECIALIST_SYSTEM_PROMPT
        finish_tool = agent_finish
        name = f"docket-{role}"
        base_tools = [http_request, finding, *_COMMON_TOOLS]
        # Only the SQLi specialist gets a shell: it's the one role with a real reason
        # to drive an external tool (sqlmap). cmdi proves itself with timing over HTTP
        # and xss needs a browser, so handing either a shell would widen the blast
        # radius for nothing.
        if role == "sqli":
            base_tools.append(shell)
        # Only the XSS specialist gets a browser — it's the one role whose proof
        # requires a real DOM executing the payload.
        if role == "xss":
            base_tools.append(browser)
    elif role == "recon":
        # Same read-only posture as triage, plus list_source: an agent that cannot see
        # the repository's shape reads files at random and burns its budget.
        instructions = RECON_SYSTEM_PROMPT
        finish_tool = record_surface
        name = "docket-recon"
        base_tools = [list_source, read_source, search_source, thinking, notes]
    elif role == "triage":
        # Reads source, never touches the target. No http_request, no shell, no
        # browser: judging whether a line is reachable needs the repository, and a
        # network tool here would only widen the blast radius for nothing.
        instructions = TRIAGE_SYSTEM_PROMPT
        finish_tool = triage_verdict
        name = "docket-triage"
        base_tools = [read_source, search_source, thinking, notes]
    else:
        raise ValueError(f"unknown role: {role!r}")

    common: dict[str, Any] = {
        "name": name,
        "instructions": instructions,
        "tools": [*base_tools, *(extra_tools or []), finish_tool],
        "model": model or LitellmModel(
            model=config.llm, api_key=config.llm_api_key, base_url=config.llm_base_url,
        ),
        "tool_use_behavior": _finish_tool_use_behavior,
        # NO output_type, deliberately. Declaring one makes the SDK send
        # response_format=json_schema, and DeepSeek V4 Pro (Azure AI Foundry) then
        # returns zero tool calls for the rest of the run — measured directly against
        # the endpoint: tools+tool_choice=required alone gives a tool call, adding the
        # json_schema gives tool_calls=0 AND empty content, so the loop spins to
        # MaxTurnsExceeded having tested nothing. Its other job (keeping the finish
        # tool's dict from being stringified) is now done losslessly by
        # ScanContext.final_result.
        #
        # Removing it also closes the README's "agents can stop without a finish tool"
        # gap at the root: with no output_type there is no schema for a stray message
        # to match, and tool_choice="required" below blocks the bare-text exit.
        # Previously built and then dropped on the floor (the README's "per-request
        # model settings are not applied" gap). Applying them is what carries
        # tool_choice="required", without which an agent can end a run on a plain
        # message that happens to match output_type — see build_model_settings.
        "model_settings": build_model_settings(config.llm),
    }
    if sandbox is not None and supports_hosted_tools(common["model"]):
        from docket.runtime.sdk_session import DocketSandboxSession

        # SandboxAgent + capabilities is why tools/shell/, apply_patch/ and
        # view_image/ are README-only: those tools come from the SDK, aimed at a
        # real container by this session.
        session = DocketSandboxSession(sandbox)
        return SandboxAgent[ScanContext](
            **common, capabilities=[Filesystem(session=session), Shell(session=session)],
        )
    # Plain Agent. Two cases reach here, and neither loses the container:
    #   - no sandbox: the SDK's native shell/filesystem would have nowhere safe to run
    #   - a ChatCompletions model: hosted tools cannot be sent at all (see
    #     supports_hosted_tools)
    # docket's `shell` and `browser` are its OWN function tools that reach the
    # container through the RPC shim, so a specialist keeps every capability its
    # prompt actually uses. Only the SDK's apply_patch/view_image drop out, and the
    # README already calls those documentation stubs.
    return Agent[ScanContext](**common)


def demo() -> None:
    """Regression guard for the hosted-tools incompatibility.

    A sandboxed scan on a LiteLLM model used to raise UserError before its first turn
    (see supports_hosted_tools). Nothing caught it, because the test suite's scripted
    model is not a LitellmModel and so took the SandboxAgent branch that real runs
    never reach.
    """
    from docket.config.settings import Config

    cfg = Config(llm="openai/DeepSeek-V4-Pro", llm_api_key="k", max_cost_usd=1.0,
                 max_child_cost_usd=0.5, max_agents=2, llm_base_url="https://x/openai/v1/")
    sentinel = object()  # stands in for a Sandbox; never dereferenced on this path

    live = LitellmModel(model=cfg.llm, api_key=cfg.llm_api_key, base_url=cfg.llm_base_url)
    assert supports_hosted_tools(live) is False
    assert supports_hosted_tools(None) is True

    # THE BUG: sandbox on + LiteLLM model must NOT be a SandboxAgent.
    agent = build_agent("sqli", cfg, model=live, sandbox=sentinel)
    assert not isinstance(agent, SandboxAgent), "LiteLLM + sandbox must use a plain Agent"
    assert isinstance(agent, Agent)

    # ...and the container is still reachable: shell/browser are docket's own tools.
    names = {t.name for t in agent.tools}
    assert "shell" in names, names          # sqli drives sqlmap in the container
    assert "http_request" in names, names
    assert "finding" in names, names
    assert "apply_patch" not in names       # the SDK hosted tool that could not be sent

    # xss keeps its browser; cmdi gets neither shell nor browser.
    assert "browser" in {t.name for t in build_agent("xss", cfg, model=live, sandbox=sentinel).tools}
    cmdi = {t.name for t in build_agent("cmdi", cfg, model=live, sandbox=sentinel).tools}
    assert "shell" not in cmdi and "browser" not in cmdi, cmdi

    # No sandbox at all is still a plain Agent.
    assert not isinstance(build_agent("root", cfg, model=live), SandboxAgent)
    print("agents.factory: ok")


if __name__ == "__main__":
    demo()
