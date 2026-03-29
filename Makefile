.PHONY: build hash serve test

# Inline src/core.js into src/template.html → dist/vaultless.html
build:
	python3 build.py

# Run tests headlessly via Playwright (pip install playwright && playwright install chromium --with-deps)
test:
	python3 tests/run_headless.py

# Build and print the SHA-256 of the distribution file
hash: build
	@echo ""
	@echo "Publish this hash alongside the file so users can verify integrity:"
	@sha256sum dist/vaultless.html

# Serve the project locally for development and testing.
# Tests: http://localhost:8080/tests/
# App:   http://localhost:8080/src/template.html  (live, no build needed)
# Dist:  http://localhost:8080/dist/vaultless.html
serve:
	python3 -m http.server 8080 --directory .
