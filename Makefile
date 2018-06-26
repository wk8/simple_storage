.DEFAULT_GOAL := all
SHELL := /usr/bin/env bash

.PHONY: all
all: activate requirements run

.PHONY: run
run: activate
	. activate && FLASK_APP=app flask run

.PHONY: test
test: activate
	. activate && pytest --capture=no

.PHONY: lint
lint: activate
	. activate && pycodestyle app test

activate: venv
	@ [ -f activate ] || (ln -s venv/bin/activate . && $(MAKE) requirements)

venv:
	@ [ -d venv ] || python3 -m venv venv

.PHONY: requirements
requirements: activate
	. activate && venv/bin/pip install -r requirements.txt

.PHONY: freeze
freeze: activate
	. activate && venv/bin/pip freeze > requirements.txt
