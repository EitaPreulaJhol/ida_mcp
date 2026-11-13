# ida_mcp dev tasks. Runtime stays dependency-free; these targets use dev-only
# tools (ruff/mypy/coverage) that you install with: pip install -e ".[dev]"
PYTHON ?= python3

.PHONY: help test inventory skills lint fmt typecheck crosscheck idalib coverage package clean

help:
	@echo "Targets:"
	@echo "  test       - run the standalone test suite (no IDA needed)"
	@echo "  inventory  - registry <-> README <-> profiles drift guard"
	@echo "  skills     - mirror skills/ (source of truth) into .pi/skills/"
	@echo "  lint       - ruff check ."
	@echo "  fmt        - ruff check --fix ."
	@echo "  typecheck  - mypy on the pure (non-IDA) modules"
	@echo "  crosscheck - IDAPython docs cross-check (needs IDAPYTHON_DOCS_DIR)"
	@echo "  idalib     - live sweep of every safe tool (IDA_MCP_IDALIB=1 + binary)"
	@echo "  coverage   - run suite under coverage (informational)"
	@echo "  package    - build the plugin zip into dist/"
	@echo "  clean      - remove caches and dist/"

test:
	$(PYTHON) tests/run_all.py

inventory:
	$(PYTHON) tests/tool_inventory_test.py

# skills/ is canonical; .pi/skills/ is a byte-for-byte mirror for Pi
# (tests/skills_sync_test.py fails when they drift).
skills:
	rm -rf .pi/skills
	mkdir -p .pi
	cp -R skills .pi/skills
	$(PYTHON) tests/skills_sync_test.py

# Each tool is found as a module of $(PYTHON) first (pip/--user installs that
# put no script on PATH), then on PATH. if/else (not `a && b || c`) so a real
# lint/type failure fails the target instead of printing "not installed".
RUFF = $(shell $(PYTHON) -m ruff --version >/dev/null 2>&1 && echo "$(PYTHON) -m ruff" || \
	(command -v ruff >/dev/null 2>&1 && echo ruff))
MYPY = $(shell $(PYTHON) -m mypy --version >/dev/null 2>&1 && echo "$(PYTHON) -m mypy" || \
	(command -v mypy >/dev/null 2>&1 && echo mypy))
COVERAGE = $(shell $(PYTHON) -m coverage --version >/dev/null 2>&1 && echo "$(PYTHON) -m coverage" || \
	(command -v coverage >/dev/null 2>&1 && echo coverage))

lint:
	@if [ -n "$(RUFF)" ]; then $(RUFF) check .; \
	else echo "ruff not installed (pip install -e '.[dev]')"; exit 1; fi

fmt:
	@if [ -n "$(RUFF)" ]; then $(RUFF) check --fix .; \
	else echo "ruff not installed (pip install -e '.[dev]')"; exit 1; fi

typecheck:
	@if [ -n "$(MYPY)" ]; then $(MYPY); \
	else echo "mypy not installed (pip install -e '.[dev]')"; exit 1; fi

crosscheck:
	$(PYTHON) tests/idadocs_crosscheck_test.py

# Live all-tools sweep; skips green without IDA_MCP_IDALIB=1 and a binary:
#   IDA_MCP_IDALIB=1 IDA_MCP_IDALIB_BINARY=/bin/ls make idalib
idalib:
	$(PYTHON) tests/idalib_all_tools_test.py

coverage:
	@if [ -n "$(COVERAGE)" ]; then \
		$(COVERAGE) erase; \
		COVERAGE_PROCESS_START=$(CURDIR)/pyproject.toml $(PYTHON) tests/run_all.py; \
		$(COVERAGE) combine 2>/dev/null || true; \
		$(COVERAGE) report; \
	else echo "coverage not installed (pip install -e '.[dev]')"; exit 1; fi

package:
	$(PYTHON) scripts/package.py

clean:
	rm -rf dist build .ruff_cache .mypy_cache .coverage .coverage.*
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
