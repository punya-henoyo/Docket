"""Pre-flight environment checks.

Run before a scan starts so a missing prerequisite is reported in one clear message
up front, rather than surfacing as a confusing failure ten turns in — an agent that
gets "no sandbox available" from every shell call has already burned budget by then.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass(slots=True)
class EnvironmentReport:
    llm_configured: bool = False
    llm_model: str | None = None
    api_key_source: str | None = None
    docker_available: bool = False
    docker_error: str | None = None
    search_configured: bool = False
    search_provider: str | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


# LiteLLM auto-detects a provider's own key, so LLM_API_KEY is only the fallback.
_PROVIDER_KEY_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}


def check_docker(timeout: float = 10.0) -> tuple[bool, str | None]:
    if shutil.which("docker") is None:
        return False, "docker CLI not found on PATH"
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "docker did not respond (is Docker Desktop running?)"
    if proc.returncode != 0:
        return False, (proc.stderr.strip().splitlines() or ["docker daemon unreachable"])[0]
    return True, None


def check_environment(*, require_sandbox: bool = True, require_llm: bool = True) -> EnvironmentReport:
    """`require_llm=False` is for `--static-only` runs: no agent ever spawns there, so
    DOCKET_LLM/an API key would be a check for a prerequisite that scan doesn't have."""
    report = EnvironmentReport()

    model = (os.environ.get("DOCKET_LLM") or "").strip()
    report.llm_model = model or None
    if not model:
        if require_llm:
            report.errors.append(
                "DOCKET_LLM is not set. Example: DOCKET_LLM=anthropic/claude-sonnet-5 "
                "(any LiteLLM provider/model string). A .env file is picked up automatically."
            )
    else:
        provider = model.split("/", 1)[0].lower() if "/" in model else "openai"
        provider_var = _PROVIDER_KEY_VARS.get(provider)
        if os.environ.get("LLM_API_KEY"):
            report.llm_configured, report.api_key_source = True, "LLM_API_KEY"
        elif provider_var and os.environ.get(provider_var):
            report.llm_configured, report.api_key_source = True, provider_var
        elif require_llm:
            hint = f" or {provider_var}" if provider_var else ""
            report.errors.append(f"No API key found. Set LLM_API_KEY{hint} for {model!r}.")

    report.docker_available, report.docker_error = check_docker()
    if require_sandbox and not report.docker_available:
        report.errors.append(
            f"Docker is required for the sandbox ({report.docker_error}). "
            "Start Docker, or pass --no-sandbox to run without it "
            "(which disables the shell and browser tools)."
        )
    elif not require_sandbox and not report.docker_available:
        report.warnings.append(
            "Running without the sandbox: shell (sqlmap) and browser (XSS execution "
            "proof) are unavailable, so some findings can only be inferred, not proven."
        )

    provider = (os.environ.get("DOCKET_SEARCH_PROVIDER") or "").strip().lower()
    if provider and os.environ.get("DOCKET_SEARCH_API_KEY"):
        report.search_configured, report.search_provider = True, provider
    else:
        report.warnings.append(
            "web_search is not configured (DOCKET_SEARCH_PROVIDER + DOCKET_SEARCH_API_KEY). "
            "Agents will work from what they can observe on the target."
        )
    return report


def format_report(report: EnvironmentReport) -> str:
    lines = []
    for error in report.errors:
        lines.append(f"error: {error}")
    for warning in report.warnings:
        lines.append(f"warning: {warning}")
    return "\n".join(lines)


def demo() -> None:
    saved = {k: os.environ.pop(k, None) for k in
             ("DOCKET_LLM", "LLM_API_KEY", "ANTHROPIC_API_KEY", "DOCKET_SEARCH_PROVIDER", "DOCKET_SEARCH_API_KEY")}
    try:
        missing = check_environment(require_sandbox=False)
        assert not missing.ok and any("DOCKET_LLM" in e for e in missing.errors)

        os.environ["DOCKET_LLM"] = "anthropic/claude-sonnet-5"
        no_key = check_environment(require_sandbox=False)
        assert not no_key.ok and any("ANTHROPIC_API_KEY" in e for e in no_key.errors), no_key.errors

        # A provider's own key satisfies it — LLM_API_KEY is only the fallback.
        os.environ["ANTHROPIC_API_KEY"] = "sk-test"
        ok = check_environment(require_sandbox=False)
        assert ok.llm_configured and ok.api_key_source == "ANTHROPIC_API_KEY"
        assert ok.ok, ok.errors
        assert any("web_search is not configured" in w for w in ok.warnings)

        os.environ["DOCKET_SEARCH_PROVIDER"] = "tavily"
        os.environ["DOCKET_SEARCH_API_KEY"] = "tvly-x"
        searched = check_environment(require_sandbox=False)
        assert searched.search_configured and searched.search_provider == "tavily"
        assert format_report(searched) == "" or "warning" in format_report(searched)

        # --static-only: no DOCKET_LLM/key needed at all, since no agent ever spawns.
        os.environ.pop("DOCKET_LLM", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)
        static = check_environment(require_sandbox=False, require_llm=False)
        assert static.ok, static.errors
    finally:
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
    print("interface.environment: ok")


if __name__ == "__main__":
    demo()
