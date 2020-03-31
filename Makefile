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

prepare-config:
	$(SED) "s@use = config:.*@use = config:$(CKAN_PATH)/test-core.ini@" -i $(TEST_INI_PATH)

test: prepare-config dev-requirements.txt
	$(PIP) install -r dev-requirements.txt
	$(ISORT) -rc -df -c $(PACKAGE_DIR)
	$(FLAKE8) --statistics $(PACKAGE_DIR)
	$(PASTER) --plugin=ckan db init -c $(TEST_INI_PATH)
	$(NOSETESTS) --ckan \
	      --with-pylons=$(TEST_INI_PATH) \
          --nologcapture \
          --with-doctest

coverage: prepare-config test
	$(NOSETESTS) --ckan \
	      --with-pylons=$(TEST_INI_PATH) \
          --nologcapture \
		  --with-coverage \
          --cover-package=$(PACKAGE_NAME) \
          --cover-inclusive \
          --cover-erase \
          --cover-tests
