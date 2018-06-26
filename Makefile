.DEFAULT_GOAL := run
SHELL := /usr/bin/env bash

run: activate
	. activate && flask run

activate: venv
	@ [ -f activate ] || ln -s venv/bin/activate .

requirements:
	venv/bin/pip install -r requirements.txt

venv:
	@ [ -d venv ] || python3 -m venv venv

freeze:
	venv/bin/pip freeze > requirements.txt
