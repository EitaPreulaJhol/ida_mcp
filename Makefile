# ida_mcp dev tasks. Runtime stays dependency-free; these targets use dev-only
# tools (ruff/mypy/coverage) that you install with: pip install -e ".[dev]"
PYTHON ?= python3

.PHONY: help test inventory lint fmt typecheck crosscheck coverage package clean

help:
	@echo "Targets:"
	@echo "  test       - run the standalone test suite (no IDA needed)"
	@echo "  inventory  - registry <-> README <-> profiles drift guard"
	@echo "  lint       - ruff check ."
	@echo "  fmt        - ruff check --fix ."
	@echo "  typecheck  - mypy on the pure (non-IDA) modules"
	@echo "  crosscheck - IDAPython docs cross-check (needs IDAPYTHON_DOCS_DIR)"
	@echo "  coverage   - run suite under coverage (informational)"
	@echo "  package    - build the plugin zip into dist/"
	@echo "  clean      - remove caches and dist/"

test:
	$(PYTHON) tests/run_all.py

inventory:
	$(PYTHON) tests/tool_inventory_test.py

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check . || \
		echo "ruff not installed (pip install -e '.[dev]')"

fmt:
	@command -v ruff >/dev/null 2>&1 && ruff check --fix . || \
		echo "ruff not installed (pip install -e '.[dev]')"

typecheck:
	@command -v mypy >/dev/null 2>&1 && mypy || \
		echo "mypy not installed (pip install -e '.[dev]')"

crosscheck:
	$(PYTHON) tests/idadocs_crosscheck_test.py

coverage:
	@command -v coverage >/dev/null 2>&1 && ( \
		coverage erase; \
		COVERAGE_PROCESS_START=$(CURDIR)/pyproject.toml $(PYTHON) tests/run_all.py; \
		coverage combine 2>/dev/null || true; \
		coverage report ) || \
		echo "coverage not installed (pip install -e '.[dev]')"

package:
	$(PYTHON) scripts/package.py

clean:
	rm -rf dist build .ruff_cache .mypy_cache .coverage .coverage.*
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
