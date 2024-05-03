PACKAGE_NAME=nethsm
VENV=venv
PYTHON3=python3
PYTHON3_VENV=venv/bin/python3
CHECK_DIRS=$(PACKAGE_NAME)/ tests/

all: init

init: update-venv

# code checks
check-format:
	$(PYTHON3_VENV) -m black --check $(CHECK_DIRS)

check-import-sorting:
	$(PYTHON3_VENV) -m isort --check-only $(CHECK_DIRS)

check-style:
	$(PYTHON3_VENV) -m flake8 $(CHECK_DIRS)

check-typing:
	$(PYTHON3_VENV) -m mypy $(CHECK_DIRS)

check: check-format check-import-sorting check-style check-typing test 

semi-clean:
	rm -rf ./**/__pycache__
	rm -rf ./.mypy_cache

clean: semi-clean
	rm -rf ./$(VENV)
	rm -rf ./dist

# automatic code fixes
fix:
	$(PYTHON3_VENV) -m black $(BLACK_FLAGS) $(CHECK_DIRS)
	$(PYTHON3_VENV) -m isort $(ISORT_FLAGS) $(CHECK_DIRS)

$(VENV):
	$(PYTHON3) -m venv $(VENV)
	$(PYTHON3_VENV) -m pip install -U pip

update-venv: $(VENV)
	$(PYTHON3_VENV) -m pip install -U pip
	$(PYTHON3_VENV) -m pip install flit
	$(PYTHON3_VENV) -m flit install --symlink


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
	$(PYTHON3_VENV) -m pytest --cov nethsm --cov-report=xml $(PYTEST_FLAGS)
