<?php

declare(strict_types=1);

namespace PhpSecurityLint;

use Symfony\Component\Finder\Finder;

class SecurityLinter
{
    /**
     * @var array<string, string>
     */
    private array $insecureFunctions = [
        // Debug functions
        'var_dump'              => 'Debug function that should not be used in production',
        'print_r'               => 'Debug function that should not be used in production',
        'var_export'            => 'Debug function that should not be used in production',
        'debug_print_backtrace' => 'Debug function that should not be used in production',
        'debug_backtrace'       => 'Debug function that should not be used in production',
        'phpinfo'               => 'Information disclosure function that should not be used in production',

        // Execution functions
        'unserialize'            => 'Potentially dangerous function - use with caution',
        'eval'                   => 'Dangerous function - can execute arbitrary code',
        'exec'                   => 'Dangerous function - can execute shell commands',
        'shell_exec'             => 'Dangerous function - can execute shell commands',
        'system'                 => 'Dangerous function - can execute system commands',
        'passthru'               => 'Dangerous function - can execute system commands',

        // Database functions (when used improperly)
        'mysql_query'           => 'Deprecated MySQL function - use prepared statements instead',
        'mysqli_query'          => 'Raw query function - ensure proper sanitization or use prepared statements',

        // Output functions
        'echo'                  => 'Output function - ensure proper escaping when outputting user data',
        'print'                 => 'Output function - ensure proper escaping when outputting user data',
        'printf'                => 'Output function - ensure proper escaping when outputting user data',

    ];

    /**
     * @var array<string>
     */
    private array $excludePatterns = [];

    /**
     * @var array<string>
     */
    private array $excludedFunctions = [];

    /**
     * @var bool
     */
    private bool $strictMode = false;

    /**
     * SecurityLinter constructor.
     *
     * Initializes with default exclude patterns and insecure functions.
     */
    public function __construct()
    {
        $this->excludePatterns = [
            'vendor',
            'node_modules',
            'tests',
            'test',
        ];
    }

    /**
     * Set exclude patterns for files/directories to ignore
     *
     * @param array<string> $patterns
     */
    public function setExcludePatterns(array $patterns): void
    {
        $this->excludePatterns = $patterns;
    }

    /**
     * Set functions to exclude from linting
     *
     * @param array<string> $functions
     */
    public function setExcludedFunctions(array $functions): void
    {
        $this->excludedFunctions = array_map('strtolower', $functions);
    }

    /**
     * Enable strict mode (treat all findings as errors)
     */
    public function setStrictMode(bool $strict): void
    {
        $this->strictMode = $strict;
    }

    /**
     * Add custom insecure function
     */
    public function addInsecureFunction(string $function, string $reason): void
    {
        $this->insecureFunctions[$function] = $reason;
    }

    /**
     * Remove a function from the insecure functions list
     */
    public function removeInsecureFunction(string $function): void
    {
        unset($this->insecureFunctions[$function]);
    }

    /**
     * Get the list of functions that will be checked
     *
     * @return array<string, string>
     */
    public function getActiveFunctions(): array
    {
        if (empty($this->excludedFunctions)) {
            return $this->insecureFunctions;
        }

        return array_filter(
            $this->insecureFunctions,
            fn($key) => !in_array(strtolower($key), $this->excludedFunctions),
            ARRAY_FILTER_USE_KEY
        );
    }

    /**
     * Lint a directory or file
     *
     * @param string $path
     * @return LintResult
     */
    public function lint(string $path): LintResult
    {
        $result = new LintResult();

        if (is_file($path)) {
            $this->lintFile($path, $result);
        } elseif (is_dir($path)) {
            $this->lintDirectory($path, $result);
        } else {
            $result->addError("Path not found: {$path}");
        }

        return $result;
    }

    /**
     * Lint a directory
     */
    private function lintDirectory(string $directory, LintResult $result): void
    {
        $finder = new Finder();
        $finder->files()
            ->in($directory)
            ->name('*.php')
            ->ignoreVCS(true);

        foreach ($this->excludePatterns as $pattern) {
            if (str_starts_with($pattern, './')) {
                // Pattern like ./vendor -> vendor
                $cleanPattern = ltrim($pattern, './');
                $finder->notPath($cleanPattern);
                continue;
            }

            // Handle different pattern formats
            if (str_starts_with($pattern, '*/') && str_ends_with($pattern, '/*')) {
                // Pattern like */vendor/* -> vendor
                $cleanPattern = trim($pattern, '*/');
                $finder->notPath($cleanPattern);
            } elseif (str_starts_with($pattern, '*/')) {
                // Pattern like */vendor -> vendor
                $cleanPattern = ltrim($pattern, '*/');
                $finder->notPath($cleanPattern);
            } elseif (str_ends_with($pattern, '/*')) {
                // Pattern like vendor/* -> vendor
                $cleanPattern = rtrim($pattern, '/*');
                $finder->notPath($cleanPattern);
            } elseif (str_starts_with($pattern, './')) {
                // Pattern like ./vendor -> vendor
                $cleanPattern = ltrim($pattern, './');
                $finder->notPath($cleanPattern);
            } else {
                // Use pattern as-is
                $finder->notPath($pattern);
            }
        }

        foreach ($finder as $file) {
            $this->lintFile($file->getRealPath(), $result);
        }
    }

    /**
     * Lint a single file
     */
    private function lintFile(string $filePath, LintResult $result): void
    {
        if (! is_readable($filePath)) {
            $result->addError("Cannot read file: {$filePath}");
            return;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            $result->addError("Cannot read file content: {$filePath}");
            return;
        }

        $result->incrementFilesScanned();
        $this->analyzeFileContent($filePath, $content, $result);
    }

    /**
     * Analyze file content for insecure functions
     */
    private function analyzeFileContent(string $filePath, string $content, LintResult $result): void
    {
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            $this->analyzeLine($filePath, $lineNumber + 1, $line, $result);
        }
    }

    /**
     * Analyze a single line for insecure functions
     */
    private function analyzeLine(string $filePath, int $lineNumber, string $line, LintResult $result): void
    {
        // Skip comments
        if (preg_match('/^\s*\/\//', $line) || preg_match('/^\s*\/\*/', $line) || preg_match('/^\s*\*/', $line)) {
            return;
        }

        // Get only the functions we should check (excluding the excluded ones)
        $functionsToCheck = $this->getActiveFunctions();

        foreach ($functionsToCheck as $function => $reason) {
            // Create pattern to match function calls
            $pattern = '/\b' . preg_quote($function, '/') . '\s*\(/';

            if (preg_match($pattern, $line, $matches, PREG_OFFSET_CAPTURE)) {
                $column = $matches[0][1] + 1;

                $violation = new SecurityViolation(
                    $filePath,
                    $lineNumber,
                    $column,
                    $function,
                    $reason,
                    trim($line)
                );

                $result->addViolation($violation);
            }
        }
    }
}
