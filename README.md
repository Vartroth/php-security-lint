# PHP Security Lint

A comprehensive PHP security linter designed to detect insecure functions and potential security vulnerabilities in your PHP codebase. Similar to `php-parallel-lint/php-var-dump-check` but with extended coverage for various security-related functions.

## Features

- **Comprehensive Detection**: Identifies debug functions (`var_dump`, `print_r`), and more
- **Multiple Output Formats**: Text, JSON, and table formats for different use cases
- **Flexible Configuration**: Customizable exclude patterns and strict mode
- **Severity Levels**: Categorizes violations by risk level (high, medium, low)
- **CI/CD Integration**: Perfect for automated security checks in your pipeline

## Installation

### Via Composer (Recommended)

```bash
composer require --dev vartroth/php-security-lint
```

### Global Installation

```bash
composer global require vartroth/php-security-lint
```

## Usage

### Basic Usage

```bash
# Scan a directory
./vendor/bin/php-security-lint /path/to/your/project

# Scan a single file
./vendor/bin/php-security-lint /path/to/file.php
```

### Advanced Usage

```bash
# Use table format
./vendor/bin/php-security-lint --format=table /path/to/project

# JSON output for CI/CD integration
./vendor/bin/php-security-lint --format=json /path/to/project

# Exclude specific patterns
./vendor/bin/php-security-lint --exclude="*/vendor/*" --exclude="*/tests/*" /path/to/project

# Strict mode (treat all findings as errors)
./vendor/bin/php-security-lint --strict /path/to/project

# Disable progress output
./vendor/bin/php-security-lint --no-progress /path/to/project
```

## Detected Functions

### Debug Functions (Medium Risk)
- `var_dump()` - Debug output that shouldn't be in production
- `print_r()` - Debug output that shouldn't be in production
- `var_export()` - Debug output that shouldn't be in production
- `debug_print_backtrace()` - Debug function
- `debug_backtrace()` - Debug function
- `phpinfo()` - Information disclosure risk

### Execution functions (Hight Risk)
- `unserialize()` - 'Potentially dangerous function - use with caution',
- `eval()` - 'Dangerous function - can execute arbitrary code',
- `shell_exec()` - 'Dangerous function - can execute shell commands',
- `system()` - 'Dangerous function - can execute system commands',
- `passthru()` - 'Dangerous function - can execute system commands',

### Database Functions (Low Risk)
- `mysql_query()` - Deprecated function
- `mysqli_query()` - Raw queries (use prepared statements)

### Other Functions
- `echo()` - Output (ensure proper escaping)
- `print()` - Output (ensure proper escaping)
- `printf()` - Output (ensure proper escaping)

## Configuration

### Exclude Patterns

By default, the following patterns are excluded:
- `*/vendor/*`
- `*/node_modules/*`
- `*/tests/*`
- `*/test/*`

You can customize exclude patterns using the `--exclude` option:

```bash
./vendor/bin/php-security-lint --exclude="*/cache/*" --exclude="*/temp/*" /path/to/project
```

### Programmatic Usage

```php
<?php

use PhpSecurityLint\SecurityLinter;

$linter = new SecurityLinter();

// Set custom exclude patterns
$linter->setExcludePatterns(['*/vendor/*', '*/cache/*']);

// Enable strict mode
$linter->setStrictMode(true);

// Add custom insecure function
$linter->addInsecureFunction('my_debug_function', 'Custom debug function');

// Lint a directory
$result = $linter->lint('/path/to/project');

// Check results
if ($result->hasIssues()) {
    foreach ($result->getViolations() as $violation) {
        echo $violation->getMessage() . "\n";
    }
}
```

## Output Formats

### Text Format (Default)
```
File: /path/to/file.php
  Line 15:8 - var_dump() - Debug function that should not be used in production
    Context: var_dump($user_data);

Summary:
Files scanned: 25
Files with violations: 3
Total violations: 7
```

### JSON Format
```json
{
  "summary": {
    "files_scanned": 25,
    "files_with_violations": 3,
    "total_violations": 7,
    "total_errors": 0
  },
  "violations": [
    {
      "file": "/path/to/file.php",
      "line": 15,
      "column": 8,
      "function": "var_dump",
      "reason": "Debug function that should not be used in production",
      "context": "var_dump($user_data);",
      "severity": "medium"
    }
  ],
  "errors": []
}
```

### Table Format
```
+----------------+------+----------+----------+--------------------------------------------------+
| File           | Line | Function | Severity | Reason                                           |
+----------------+------+----------+----------+--------------------------------------------------+
| example.php    | 15   | var_dump | MEDIUM   | Debug function that should not be used in prod.. |
| another.php    | 23   | eval     | HIGH     | Code evaluation function - high security risk   |
+----------------+------+----------+----------+--------------------------------------------------+

Summary: 7 violations in 3 files
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Lint

on: [push, pull_request]

jobs:
  security-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'

      - name: Install dependencies
        run: composer install --no-dev --optimize-autoloader

      - name: Run security lint
        run: ./vendor/bin/php-security-lint --format=json --no-progress src/
```

### GitLab CI

```yaml
security-lint:
  image: php:8.1
  before_script:
    - curl -sS https://getcomposer.org/installer | php
    - php composer.phar install --no-dev
  script:
    - ./vendor/bin/php-security-lint --format=json --no-progress src/
  only:
    - merge_requests
    - master
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Lint') {
            steps {
                sh 'composer install --no-dev'
                sh './vendor/bin/php-security-lint --format=json --no-progress src/ > security-report.json'
                archiveArtifacts artifacts: 'security-report.json'
            }
        }
    }
}
```

## Exit Codes

- `0` - No violations found
- `1` - Violations found or errors occurred

## Best Practices

### 1. Regular Scanning
Run the linter regularly as part of your development workflow:

```bash
# Add to your composer.json scripts
{
  "scripts": {
    "security-check": "php-security-lint src/",
    "security-check-strict": "php-security-lint --strict src/"
  }
}
```

### 2. Pre-commit Hooks
Integrate with Git pre-commit hooks using tools like `pre-commit`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: php-security-lint
        name: PHP Security Lint
        entry: ./vendor/bin/php-security-lint
        language: system
        files: \.php$
        args: ['--no-progress']
```

### 3. Custom Configuration
Create a configuration file for your project:

```php
<?php
// security-lint-config.php

return [
    'exclude_patterns' => [
        '*/vendor/*',
        '*/cache/*',
        '*/storage/logs/*',
    ],
    'custom_functions' => [
        'dd' => 'Laravel debug function - should not be used in production',
        'dump' => 'Symfony debug function - should not be used in production',
    ],
    'strict_mode' => false,
];
```

## Limitations

- **Static Analysis Only**: This tool performs static analysis and may not catch dynamically constructed function calls
- **False Positives**: Some legitimate uses of flagged functions may be reported
- **Context Awareness**: The tool doesn't understand the full context of function usage

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
git clone https://github.com/vartroth/php-security-lint.git
cd php-security-lint
composer install
```

### Running Tests

```bash
composer test
```

### Code Style

```bash
composer cs-check
composer cs-fix
```

## Changelog

### v1.0.0
- Initial release
- Support for detecting 20+ insecure functions
- Multiple output formats (text, JSON, table)
- Configurable exclude patterns
- Severity levels for violations
- CLI interface with comprehensive options

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

If you discover any security-related issues, please email security@vartroth.com instead of using the issue tracker.

## Acknowledgments

- Inspired by `php-parallel-lint/php-var-dump-check`
- Built with Symfony Console component
- Thanks to all contributors who help make PHP applications more secure

## Similar Tools

- [php-parallel-lint/php-var-dump-check](https://github.com/php-parallel-lint/PHP-Var-Dump-Check) - Focuses on var_dump detection
- [phpstan/phpstan](https://github.com/phpstan/phpstan) - Comprehensive static analysis
- [vimeo/psalm](https://github.com/vimeo/psalm) - Static analysis with security focus
- [squizlabs/php_codesniffer](https://github.com/squizlabs/PHP_CodeSniffer) - Code style and quality checker