-include variables.mk

CHECK_DIRS := nethsm/ tests/

PYTHON ?= poetry run python
RUFF ?= poetry run ruff
ISORT ?= poetry run isort
FLAKE8 ?= poetry run flake8
MYPY ?= poetry run mypy

.PHONY: install
install:
	poetry sync --with dev

.PHONY: lock
lock:
	poetry lock

.PHONY: update
update:
	poetry update --with dev

# code checks
check-format:
	$(RUFF) format --check $(CHECK_DIRS)

check-import-sorting:
	$(ISORT) --check-only $(CHECK_DIRS)

check-style:
	$(FLAKE8) $(CHECK_DIRS)

check-typing:
	$(MYPY) $(CHECK_DIRS)

check-poetry:
	poetry check

check: check-format check-import-sorting check-style check-typing check-poetry

semi-clean:
	rm -rf ./**/__pycache__
	rm -rf ./.mypy_cache

clean: semi-clean
	rm -rf ./$(VENV)
	rm -rf ./dist

# automatic code fixes
fix:
	$(RUFF) format $(CHECK_DIRS)
	$(ISORT) $(ISORT_FLAGS) $(CHECK_DIRS)

OPENAPI_OUTPUT_DIR=${PWD}/tmp/openapi-client

nethsm-api.yaml:
	curl "https://nethsmdemo.nitrokey.com/api_docs/nethsm-api.yaml" --output nethsm-api.yaml

# Generates the OpenAPI client for the NetHSM REST API
.PHONY: nethsm-client
nethsm-client: nethsm-api.yaml
	rm -r nethsm/client
	rm -r "${OPENAPI_OUTPUT_DIR}"
	mkdir -p "${OPENAPI_OUTPUT_DIR}"
	cp nethsm-api.yaml "${OPENAPI_OUTPUT_DIR}"
	docker run --rm -ti -v "${OPENAPI_OUTPUT_DIR}:/out" \
		openapijsonschematools/openapi-json-schema-generator-cli:3.2.1 generate \
		-i=/out/nethsm-api.yaml \
		-g=python -o=/out/python --package-name=nethsm.client
	cp -r "${OPENAPI_OUTPUT_DIR}/python/src/nethsm/client" nethsm

.PHONY: test
test:
	$(PYTHON) -m doctest nethsm/__init__.py
	$(PYTHON) -m pytest --cov nethsm --cov-report=xml $(PYTEST_FLAGS)
