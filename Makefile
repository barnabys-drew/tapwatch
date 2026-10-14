.PHONY: test lint eval

test:
	python3 -m pytest -q

lint:
	ruff check src tests tools

# Usage: make eval ZEEK_DIR=eval/out/sample LABELS=eval/labels.example.yaml
eval:
	PYTHONPATH=src python3 -m tapwatch.cli eval --zeek-dir $(ZEEK_DIR) --labels $(LABELS)
