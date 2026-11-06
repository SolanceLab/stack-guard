# `make test` runs every test in this room, whatever the language.
.PHONY: test
test:
	python3 -m unittest discover -s tests -p 'test_*.py'
