"""The `browser` tool: a persistent Playwright/Chromium page the agent drives.

This is what upgrades an XSS finding from "my payload appeared in the HTML" (an
inference) to "the payload EXECUTED in a real DOM" (a proof). The mechanism is
page.on("dialog"): navigate to a reflected `alert()` payload and a non-null
dialog_message coming back IS the proof — no screenshot interpretation required.

Runs INSIDE the container. Playwright is imported lazily so a shim built without it
returns an error result instead of failing to boot.

Single page, no multi-tab: the targets in scope have no cross-page navigation flow to
test, so tabs would buy nothing. Cheap to add if a target ever
grows a real login-session flow.
"""
from __future__ import annotations

import uuid
from pathlib import Path

_session: "BrowserSession | None" = None


class BrowserSession:
    def __init__(self) -> None:
        self._pw = None
        self._browser = None
        self._page = None
        self.dialogs: list[str] = []
        self.console: list[str] = []

    def ensure(self):
        if self._page is not None:
            return self._page
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        # --no-sandbox is required because Chromium cannot start its own sandbox as
        # root without extra kernel privileges. That is acceptable precisely BECAUSE
        # the Docker container is already the isolation boundary — we are not removing
        # the outer sandbox, only Chromium's redundant inner one.
        self._browser = self._pw.chromium.launch(
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        self._page = self._browser.new_page()

        def _on_dialog(dialog) -> None:
            # MUST dismiss, or the page blocks forever waiting on the dialog — and a
            # blocked page would hang every later tool call on this session.
            self.dialogs.append(dialog.message)
            try:
                dialog.dismiss()
            except Exception:
                pass

        self._page.on("dialog", _on_dialog)
        self._page.on("console", lambda msg: self.console.append(f"{msg.type}: {msg.text}"))
        return self._page

    def close(self) -> None:
        for closer in (
            getattr(self._browser, "close", None),
            getattr(self._pw, "stop", None),
        ):
            if closer is not None:
                try:
                    closer()
                except Exception:
                    pass
        self._pw = self._browser = self._page = None
        self.dialogs.clear()
        self.console.clear()


def _reset_globals() -> None:
    global _session
    if _session is not None:
        _session.close()
        _session = None


def browser_close() -> dict:
    _reset_globals()
    return {"ok": True}


def browser(
    run_dir: Path,
    action: str,
    url: str | None = None,
    selector: str | None = None,
    text: str | None = None,
    script: str | None = None,
    timeout_sec: int = 10,
) -> dict:
    """Drive the page. `dialog_message` is populated whenever the page raised an
    alert/confirm/prompt during THIS action — the XSS execution proof."""
    global _session
    if action == "close":
        return browser_close()

    if _session is None:
        _session = BrowserSession()

    try:
        page = _session.ensure()
    except ImportError as exc:
        return {"ok": False, "error": f"playwright not available in this sandbox: {exc}"}

    # Only report dialogs/console raised by THIS action, not the whole session.
    _session.dialogs.clear()
    _session.console.clear()
    timeout_ms = max(1, int(timeout_sec)) * 1000

    result: dict = {"ok": True, "text": None, "html": None, "screenshot_path": None, "error": None}
    try:
        if action == "navigate":
            if not url:
                return {"ok": False, "error": "navigate requires `url`"}
            page.goto(url, timeout=timeout_ms, wait_until="load")
        elif action == "click":
            page.click(selector or "", timeout=timeout_ms)
        elif action == "fill":
            page.fill(selector or "", text or "", timeout=timeout_ms)
        elif action == "get_text":
            result["text"] = page.inner_text(selector) if selector else page.inner_text("body")
        elif action == "get_html":
            result["html"] = page.content()
        elif action == "evaluate":
            result["text"] = str(page.evaluate(script or ""))
        elif action == "wait_for":
            page.wait_for_selector(selector or "", timeout=timeout_ms)
        elif action == "screenshot":
            rel = Path("artifacts") / "screenshots" / f"{uuid.uuid4().hex[:12]}.png"
            out = run_dir / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(out))
            # Relative to the run dir, so the path resolves on BOTH sides of the bind
            # mount — the container writes it, the host's report reads it.
            result["screenshot_path"] = str(rel)
        else:
            return {"ok": False, "error": f"unknown action: {action!r}"}
    except Exception as exc:
        result["ok"] = False
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["url"] = page.url
    result["dialog_message"] = _session.dialogs[0] if _session.dialogs else None
    result["dialogs"] = list(_session.dialogs)
    result["console_messages"] = list(_session.console)
    return result
