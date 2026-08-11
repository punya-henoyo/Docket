# agent_browser

A persistent Playwright/Chromium page inside the sandbox.

The reason it exists: `dialog_message`. Navigating to a reflected `alert()` payload and
capturing the dialog a real DOM raises is what upgrades an XSS finding from "my payload
appeared in the HTML" (an inference) to "the payload executed" (a proof).

Single page, no multi-tab — a cut from upstream, since nothing in scope needs
cross-page flow. Chromium runs with `--no-sandbox` because the container is already the
isolation boundary; that removes Chromium's redundant inner sandbox, not the outer one.
