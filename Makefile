local: dependencies-lock code-format lint

dependencies-lock:
	poetry lock --no-update

code-format:
	ruff format
	ruff check --fix

lint:
	ruff check
