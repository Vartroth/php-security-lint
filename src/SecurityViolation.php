<?php

declare(strict_types=1);

namespace PhpSecurityLint;

class SecurityViolation
{
    /**
     * SecurityViolation constructor.
     *
     * @param string $file
     * @param int $line
     * @param int $column
     * @param string $function
     * @param string $reason
     * @param string $context
     * @return void
     */
    public function __construct(
        private string $file,
        private int $line,
        private int $column,
        private string $function,
        private string $reason,
        private string $context
    ) {
    }

    /**
     * Get the file path
     * @return string
     */
    public function getFile(): string
    {
        return $this->file;
    }

    /**
     * Get the line number
     * @return int
     */
    public function getLine(): int
    {
        return $this->line;
    }

    /**
     * Get the column number
     * @return int
     */
    public function getColumn(): int
    {
        return $this->column;
    }

    /**
     * Get the insecure function name
     * @return string
     */
    public function getFunction(): string
    {
        return $this->function;
    }

    /**
     * Get the reason why this function is insecure
     * @return string
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * Get the context where the function was found
     * @return string
     */
    public function getContext(): string
    {
        return $this->context;
    }

    /**
     * Get the severity level based on function type
     * @return string
     */
    public function getSeverity(): string
    {
        $highRiskFunctions   = ['eval', 'exec', 'shell_exec', 'system', 'passthru', 'unserialize'];
        $mediumRiskFunctions = ['var_dump', 'print_r', 'phpinfo', 'debug_print_backtrace'];

        if (in_array($this->function, $highRiskFunctions)) {
            return 'high';
        } elseif (in_array($this->function, $mediumRiskFunctions)) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * Get formatted message
     */
    public function getMessage(): string
    {
        return sprintf(
            "Found insecure function '%s' at %s:%d:%d - %s",
            $this->function,
            $this->file,
            $this->line,
            $this->column,
            $this->reason
        );
    }

    /**
     * Convert to array representation
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'file'     => $this->file,
            'line'     => $this->line,
            'column'   => $this->column,
            'function' => $this->function,
            'reason'   => $this->reason,
            'context'  => $this->context,
            'severity' => $this->getSeverity(),
        ];
    }
}
