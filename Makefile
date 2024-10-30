test: test_lint

test_lint:
	pre-commit run --all-files --show-diff-on-failure
