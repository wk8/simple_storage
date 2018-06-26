.DEFAULT_GOAL := run
SHELL := /usr/bin/env bash

.PHONY: run
run: activate
	. activate && FLASK_APP=app/app.py flask run

.PHONY: test
test: activate
	. activate && pytest --capture=no

.PHONY: lint
lint: activate
	. activate && pycodestyle app test

activate: venv
	@ [ -f activate ] || ln -s venv/bin/activate .

venv:
	@ [ -d venv ] || python3 -m venv venv

.PHONY: requirements
requirements: activate
	.activate && venv/bin/pip install -r requirements.txt

.PHONY: freeze
freeze: activate
	.activate && venv/bin/pip freeze > requirements.txt
