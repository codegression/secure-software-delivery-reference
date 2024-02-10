.PHONY: demo serve test verify package
PYTHON ?= python3
demo:
	$(PYTHON) run.py
serve:
	$(PYTHON) run.py serve
test:
	$(PYTHON) -m unittest discover -s tests -v
verify:
	$(PYTHON) run.py verify
package:
	$(PYTHON) run.py package
