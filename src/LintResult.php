<?php

declare(strict_types=1);

namespace PhpSecurityLint;

class LintResult
{
    /**
     * @var array<SecurityViolation>
     */
    private array $violations = [];

    /**
     * @var array<string>
     */
    private array $errors = [];

    /**
     * @var int
     */
    private int $filesScanned = 0;

    /**
     * Add a security violation
     */
    public function addViolation(SecurityViolation $violation): void
    {
        $this->violations[] = $violation;
    }

    /**
     * Add an error
     */
    public function addError(string $error): void
    {
        $this->errors[] = $error;
    }

    /**
     * Increment files scanned counter
     */
    public function incrementFilesScanned(): void
    {
        $this->filesScanned++;
    }

    /**
     * Get all violations
     *
     * @return array<SecurityViolation>
     */
    public function getViolations(): array
    {
        return $this->violations;
    }

    /**
     * Get all errors
     *
     * @return array<string>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Get number of violations
     */
    public function getViolationCount(): int
    {
        return count($this->violations);
    }

    /**
     * Get number of errors
     */
    public function getErrorCount(): int
    {
        return count($this->errors);
    }

    /**
     * Get number of files scanned
     */
    public function getFilesScanned(): int
    {
        return $this->filesScanned;
    }

    /**
     * Check if there are any violations or errors
     */
    public function hasIssues(): bool
    {
        return ! empty($this->violations) || ! empty($this->errors);
    }

    /**
     * Get violations grouped by file
     *
     * @return array<string, array<SecurityViolation>>
     */
    public function getViolationsByFile(): array
    {
        $violationsByFile = [];

        foreach ($this->violations as $violation) {
            $file = $violation->getFile();
            if (! isset($violationsByFile[$file])) {
                $violationsByFile[$file] = [];
            }
            $violationsByFile[$file][] = $violation;
        }

        return $violationsByFile;
    }

    /**
     * Get unique files with violations
     *
     * @return array<string>
     */
    public function getFilesWithViolations(): array
    {
        $files = [];
        foreach ($this->violations as $violation) {
            $files[] = $violation->getFile();
        }

        return array_unique($files);
    }

    /**
     * Get summary statistics
     *
     * @return array<string, int>
     */
    public function getSummary(): array
    {
        return [
            'files_scanned'         => $this->filesScanned,
            'files_with_violations' => count($this->getFilesWithViolations()),
            'total_violations'      => $this->getViolationCount(),
            'total_errors'          => $this->getErrorCount(),
        ];
    }
}
