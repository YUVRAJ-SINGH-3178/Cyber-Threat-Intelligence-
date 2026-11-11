.PHONY: setup test run-experiments make-figures

setup:
	python manage.py setup

test:
	python manage.py test

run-experiments:
	python manage.py run-experiments

make-figures:
	python manage.py make-figures

