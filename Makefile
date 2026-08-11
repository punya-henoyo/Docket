.PHONY: help install check test test-fast image clean lint

help:
	@echo "install    install dependencies (uv sync)"
	@echo "check      run every module self-check"
	@echo "test       run the full test suite (needs Docker)"
	@echo "test-fast  run only tests that don't need Docker"
	@echo "image      build the sandbox container image"
	@echo "lint       ruff check + format --check (if ruff is installed)"
	@echo "clean      remove run artifacts and caches"

install:
	uv sync

image:
	docker build -f containers/Dockerfile -t docket-sandbox:latest .

# Every module carries a runnable demo(); this is the fast signal that nothing
# structural broke, and none of it needs Docker or an API key.
check:
	@set -e; for m in \
	  docket.config.settings docket.config.models \
	  docket.core.agents docket.core.paths docket.core.sessions docket.core.inputs docket.core.hooks \
	  docket.llm.context_budget docket.llm.compaction \
	  docket.report.models docket.report.dedupe docket.report.sarif docket.report.writer \
	  docket.report.state docket.report.usage \
	  docket.tools.output_store docket.tools.shell.tools docket.tools.http_request.tools \
	  docket.tools.reporting.tool docket.tools.notes.tools docket.tools.todo.tools \
	  docket.tools.thinking.tool docket.tools.respond.tool docket.tools.web_search.tool \
	  docket.tools.load_skill.tool \
	  docket.runtime.sdk_session \
	  docket.interface.utils docket.interface.environment docket.interface.scan_setup \
	  docket.interface.cli_args docket.interface.interactive docket.interface.update_check \
	  docket.interface.tui.backend.protocol docket.interface.tui.backend.projection \
	  docket.interface.tui.backend.messages docket.interface.tui.live_view docket.interface.tui.runtime \
	  docket.interface.viewer.transcript docket.interface.viewer.server docket.interface.viewer.cli \
	  docket.telemetry.logging docket.utils.resource_paths docket.utils.secret_files ; do \
	  uv run python -m $$m >/dev/null 2>&1 && echo "ok   $$m" || { echo "FAIL $$m"; exit 1; }; \
	done

test: image
	@set -e; for f in tests/test_*.py; do \
	  uv run python $$f >/dev/null 2>&1 && echo "ok   $$f" || { echo "FAIL $$f"; exit 1; }; \
	done

test-fast:
	@set -e; for f in tests/test_report.py tests/test_coordinator.py tests/test_tools.py \
	                  tests/test_agent_loop_mock.py tests/test_multiagent_mock.py \
	                  tests/test_budget.py tests/test_viewer.py ; do \
	  uv run python $$f >/dev/null 2>&1 && echo "ok   $$f" || { echo "FAIL $$f"; exit 1; }; \
	done

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check docket tests && ruff format --check docket tests \
	  || echo "ruff not installed — skipping (uv tool install ruff)"

clean:
	rm -rf docket_runs
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
