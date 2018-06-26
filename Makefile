.DEFAULT_GOAL := run
SHELL := /usr/bin/env bash

.PHONY: run
run: activate
	. activate && FLASK_APP=app/app.py flask run

.PHONY: test
test: activate
	. activate && pytest

activate: venv
	@ [ -f activate ] || ln -s venv/bin/activate .

.PHONY: requirements
requirements:
	venv/bin/pip install -r requirements.txt

venv:
	@ [ -d venv ] || python3 -m venv venv

.PHONY: freeze
freeze:
	venv/bin/pip freeze > requirements.txt
