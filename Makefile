# Makefile for ckanext-versions

PACKAGE_DIR := ckanext/authz_service
PACKAGE_NAME := ckanext.authz_service

SHELL := bash
PIP := pip
PIP_COMPILE := pip-compile
ISORT := isort
FLAKE8 := flake8
NOSETESTS := nosetests
PASTER := paster

# Find GNU sed in path (on OS X gsed should be preferred)
SED := $(shell which gsed sed | head -n1)

TEST_INI_PATH := ./test.ini
CKAN_PATH := ../ckan


dev-requirements.txt: dev-requirements.in
	$(PIP_COMPILE) --no-index dev-requirements.in -o dev-requirements.txt

requirements.txt: requirements.in
	$(PIP_COMPILE) --no-index requirements.in -o requirements.txt

.$(TEST_INI_PATH).sentinel: $(TEST_INI_PATH) $(CKAN_PATH)/test-core.ini
	$(SED) "s@use = config:.*@use = config:$(CKAN_PATH)/test-core.ini@" -i $(TEST_INI_PATH)
	@touch $@

.test-env.sentinel: .$(TEST_INI_PATH).sentinel dev-requirements.txt
	$(PIP) install -r dev-requirements.txt
	$(PASTER) --plugin=ckan db init -c $(TEST_INI_PATH)
	@touch $@

.tests-passed.sentinel: .test-env.sentinel $(shell find $(PACKAGE_DIR) -type f) .flake8 .isort.cfg
	$(ISORT) -rc -df -c $(PACKAGE_DIR)
	$(FLAKE8) --statistics $(PACKAGE_DIR)
	$(NOSETESTS) --ckan \
	      --with-pylons=$(TEST_INI_PATH) \
          --nologcapture \
          --with-doctest
	@touch $@

test: .tests-passed.sentinel
.PHONY: test

.coverage: .tests-passed.sentinel $(shell find $(PACKAGE_DIR) -type f) .coveragerc
	$(NOSETESTS) --ckan \
	      --with-pylons=$(TEST_INI_PATH) \
          --nologcapture \
		  --with-coverage \
          --cover-package=$(PACKAGE_NAME) \
          --cover-inclusive \
          --cover-erase \
          --cover-tests

coverage: .coverage
.PHONY: coverage
