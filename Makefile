.PHONY: help install run web test clean

help:
	@echo "Available commands:"
	@echo "  make install   - Install dependencies"
	@echo "  make run       - Run the scanner"
	@echo "  make web       - Run the Flask web app"
	@echo "  make test      - Run tests"
	@echo "  make clean     - Clean temporary files"

install:
	pip install -r requirements.txt

run:
	python src/main.py . --output report.html

web:
	python src/web_app.py

test:
	pytest tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/
