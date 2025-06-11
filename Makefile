.PHONY: help install test lint cs-check cs-fix clean build

# Default target
help:
	@echo "Available targets:"
	@echo "  install    - Install dependencies"
	@echo "  test       - Run tests"
	@echo "  lint       - Run security lint on src/"
	@echo "  cs-check   - Check coding standards"
	@echo "  cs-fix     - Fix coding standards"
	@echo "  clean      - Clean up generated files"
	@echo "  build      - Build the project"
	@echo "  release    - Create a release"

# Install dependencies
install:
	composer install

# Run tests
test:
	./vendor/bin/phpunit

# Run security lint on the source code
lint:
	./bin/php-security-lint src/

# Check coding standards
cs-check:
	./vendor/bin/phpcs

# Fix coding standards
cs-fix:
	./vendor/bin/phpcbf

# Clean up generated files
clean:
	rm -rf vendor/
	rm -rf .phpunit.cache/
	rm -f .phpunit.result.cache
	rm -f composer.lock

# Build the project (install dependencies and run tests)
build: install test cs-check lint

# Create a release (for maintainers)
release: clean install test cs-check
	@echo "Project is ready for release"
	@echo "Remember to:"
	@echo "1. Update version in composer.json"
	@echo "2. Update CHANGELOG.md"
	@echo "3. Create git tag"
	@echo "4. Push to repository"