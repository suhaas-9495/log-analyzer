# Log Analyzer - build, test and run targets.  `make help` lists them.
#
# Override any variable on the command line, e.g.
#   make run FILE=/var/log/app.log CONFIG=configs/examples/minimal.yaml
#   make install PYTHON=python3.12

PYTHON  ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
CONFIG  ?= configs/config.yaml
FILE    ?= data/sample/test_logs.txt
LARGE   := data/sample/large_test_logs.txt
REPORTS ?= reports
IMAGE   ?= log-analyzer:latest
PORT    ?= 8080
LINES   ?= 100000

.DEFAULT_GOAL := help
.PHONY: help install build lint format typecheck test test-fast check data run run-large \
        run-json stream serve demo bench robustness report docker-build docker-test \
        docker-run docker-serve clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ------------------------------------------------------------------------------ setup
$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --quiet --upgrade pip

install: $(BIN)/python ## Create .venv and install the package with dev dependencies
	$(BIN)/pip install --quiet -e ".[dev]"
	@echo "Installed. Try: make run"

build: install ## Build wheel and sdist into dist/
	$(BIN)/python -m build --outdir dist .

# ----------------------------------------------------------------------------- checks
lint: install ## Lint and format check (ruff)
	$(BIN)/ruff check src tests scripts
	$(BIN)/ruff format --check src tests scripts

format: install ## Auto-format and apply safe lint fixes
	$(BIN)/ruff format src tests scripts
	$(BIN)/ruff check --fix src tests scripts

typecheck: install ## Static type check (mypy --strict)
	$(BIN)/mypy

test: install ## Run all tests with coverage (fails under 85%)
	$(BIN)/pytest --cov --cov-report=term-missing

test-fast: install ## Run tests except the slower performance/acceptance ones
	$(BIN)/pytest -m "not perf"

check: lint typecheck test ## Lint + type check + tests (what CI runs)

# ------------------------------------------------------------------------------- run
data: $(LARGE) ## Unpack the 100k-line sample log

$(LARGE): data/sample/large_test_logs.txt.zip
	$(PYTHON) -c "import zipfile; zipfile.ZipFile('$<').extract('large_test_logs.txt', 'data/sample')"
	@touch $@

run: install ## Analyze FILE (default: 10k sample) and print the dashboard
	$(BIN)/log-analyzer --file $(FILE) --config $(CONFIG)

run-large: install data ## Analyze the 100k-line sample
	$(BIN)/log-analyzer --file $(LARGE) --config $(CONFIG)

run-json: install ## Write a JSON report for FILE to reports/
	@mkdir -p $(REPORTS)
	$(BIN)/log-analyzer --file $(FILE) --config $(CONFIG) --format json -o $(REPORTS)/report.json
	@echo "wrote $(REPORTS)/report.json"

stream: install ## Stream FILE through stdin (live mode, as with tail -f)
	cat $(FILE) | $(BIN)/log-analyzer --config $(CONFIG)

serve: install ## Run the HTTP API on PORT
	$(BIN)/log-analyzer serve --config $(CONFIG) --port $(PORT) --log-level INFO

demo: install ## Scripted end-to-end demo (scenarios, streaming, JSON, API)
	PATH="$(abspath $(BIN)):$$PATH" bash scripts/demo.sh

bench: install ## Throughput / memory benchmark on generated data (LINES=...)
	$(BIN)/python scripts/benchmark.py --lines $(LINES)

robustness: install ## Detection accuracy across 10 randomly generated datasets
	$(BIN)/python scripts/robustness.py --seeds 10

report: install data ## Regenerate reports/ for the provided sample logs
	@mkdir -p $(REPORTS)
	$(BIN)/log-analyzer --file $(FILE) --config $(CONFIG) --color never -o $(REPORTS)/sample_10k_dashboard.txt
	$(BIN)/log-analyzer --file $(FILE) --config $(CONFIG) --format json -o $(REPORTS)/sample_10k.json
	$(BIN)/log-analyzer --file $(LARGE) --config $(CONFIG) --color never -o $(REPORTS)/sample_100k_dashboard.txt
	$(BIN)/log-analyzer --file $(LARGE) --config $(CONFIG) --format json -o $(REPORTS)/sample_100k.json
	@echo "reports written to $(REPORTS)/"

# ----------------------------------------------------------------------------- docker
docker-build: ## Build the runtime image
	docker build -t $(IMAGE) .

docker-test: ## Run lint, type check and tests inside a clean container
	docker build --target test -t $(IMAGE)-test .

docker-run: docker-build ## Analyze the bundled 10k sample in a container
	docker run --rm -t $(IMAGE)

docker-serve: docker-build ## Run the HTTP API in a container on PORT
	docker run --rm -p $(PORT):8080 $(IMAGE) serve

clean: ## Remove build artefacts, caches and generated data
	rm -rf $(VENV) build dist .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov \
	       $(REPORTS) data/generated $(LARGE) src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
