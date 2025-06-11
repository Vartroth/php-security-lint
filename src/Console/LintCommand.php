<?php

declare(strict_types=1);

namespace PhpSecurityLint\Console;

use PhpSecurityLint\SecurityLinter;
use PhpSecurityLint\SecurityViolation;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'lint',
    description: 'Lint PHP files for insecure functions',
    help: 'This command scans PHP files for potentially insecure functions like var_dump, exec, eval, etc.'
)]
class LintCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument(
                'path',
                InputArgument::REQUIRED,
                'Path to file or directory to scan'
            )
            ->addOption(
                'format',
                'f',
                InputOption::VALUE_REQUIRED,
                'Output format (text, json, table)',
                'text'
            )
            ->addOption(
                'exclude',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Exclude patterns (e.g., vendor, tests)'
            )
            ->addOption(
                'strict',
                's',
                InputOption::VALUE_NONE,
                'Strict mode - treat all findings as errors'
            )
            ->addOption(
                'no-progress',
                null,
                InputOption::VALUE_NONE,
                'Disable progress output'
            )
            ->addOption(
                'exclude-functions',
                'e',
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Disable linting for specific functions (e.g., var_dump, print_r)'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $path              = $input->getArgument('path');
        $format            = $input->getOption('format');
        $excludePatterns   = $input->getOption('exclude');
        $excludeFunctions  = $input->getOption('exclude-functions');
        $strict            = $input->getOption('strict');
        $noProgress        = $input->getOption('no-progress');

        if (! file_exists($path)) {
            $io->error("Path does not exist: {$path}");
            return Command::FAILURE;
        }

        $linter = new SecurityLinter();

        if (! empty($excludePatterns)) {
            $linter->setExcludePatterns($excludePatterns);
        }

        if (! empty($excludeFunctions)) {
            $linter->setExcludedFunctions($excludeFunctions);
            if (! $noProgress) {
                $io->info("Excluding functions from linting: " . implode(', ', $excludeFunctions));
            }
        }

        if ($strict) {
            $linter->setStrictMode(true);
        }

        if (! $noProgress) {
            $io->info("Scanning: {$path}");
        }

        $result = $linter->lint($path);

        // Handle errors
        if ($result->getErrorCount() > 0) {
            foreach ($result->getErrors() as $error) {
                $io->error($error);
            }
            return Command::FAILURE;
        }

        // Output results based on format
        return match ($format) {
            'json' => $this->outputJson($io, $result),
            'table' => $this->outputTable($io, $result),
            default => $this->outputText($io, $result, $noProgress),
        };
    }

    private function outputText(SymfonyStyle $io, $result, bool $noProgress): int
    {
        $violations = $result->getViolations();

        if (empty($violations)) {
            if (! $noProgress) {
                $io->success("No security violations found!");
                $io->info("Files scanned: " . $result->getFilesScanned());
            }
            return Command::SUCCESS;
        }

        $violationsByFile = $result->getViolationsByFile();

        foreach ($violationsByFile as $file => $fileViolations) {
            $io->section("File: {$file}");

            foreach ($fileViolations as $violation) {
                $severity     = $violation->getSeverity();
                $severityIcon = match ($severity) {
                    'high' => '🔴',
                    'medium' => '🟡',
                    default => '🔵',
                };

                $io->writeln(sprintf(
                    "  %s <comment>Line %d:%d</comment> - <fg=red>%s()</fg=red> - %s",
                    $severityIcon,
                    $violation->getLine(),
                    $violation->getColumn(),
                    $violation->getFunction(),
                    $violation->getReason()
                ));

                $io->writeln("    <fg=gray>Context: " . trim($violation->getContext()) . "</>");
            }
        }

        // Summary
        $summary = $result->getSummary();
        $io->definitionList(
            ['Files scanned' => $summary['files_scanned']],
            ['Files with violations' => $summary['files_with_violations']],
            ['Total violations' => $summary['total_violations']]
        );

        return $summary['total_violations'] > 0 ? Command::FAILURE : Command::SUCCESS;
    }

    private function outputJson(SymfonyStyle $io, $result): int
    {
        $data = [
            'summary'    => $result->getSummary(),
            'violations' => array_map(
                fn(SecurityViolation $violation) => $violation->toArray(),
                $result->getViolations()
            ),
            'errors'     => $result->getErrors(),
        ];

        $io->writeln(json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return $result->getViolationCount() > 0 ? Command::FAILURE : Command::SUCCESS;
    }

    private function outputTable(SymfonyStyle $io, $result): int
    {
        $violations = $result->getViolations();

        if (empty($violations)) {
            $io->success("No security violations found!");
            return Command::SUCCESS;
        }

        $tableData = array_map(
            fn(SecurityViolation $violation) => [
                basename($violation->getFile()),
                $violation->getLine(),
                $violation->getFunction(),
                strtoupper($violation->getSeverity()),
                $violation->getReason(),
            ],
            $violations
        );

        $io->table(
            ['File', 'Line', 'Function', 'Severity', 'Reason'],
            $tableData
        );

        // Summary
        $summary = $result->getSummary();
        $io->note("Summary: {$summary['total_violations']} violations in {$summary['files_with_violations']} files");

        return Command::FAILURE;
    }
}
