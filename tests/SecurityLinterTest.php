<?php

declare(strict_types=1);

namespace PhpSecurityLint\Tests;

use PhpSecurityLint\SecurityLinter;
use PhpSecurityLint\SecurityViolation;
use PHPUnit\Framework\TestCase;

class SecurityLinterTest extends TestCase
{
    private SecurityLinter $linter;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->linter  = new SecurityLinter();
        $this->tempDir = sys_get_temp_dir() . '/php-security-lint-tests';

        if (! is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0777, true);
        }
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tempDir);
    }

    public function testDetectsVarDump(): void
    {
        $content = '<?php var_dump($data); ?>';
        $file    = $this->createTempFile('test.php', $content);

        $result = $this->linter->lint($file);

        $this->assertCount(1, $result->getViolations());
        $violation = $result->getViolations()[0];
        $this->assertEquals('var_dump', $violation->getFunction());
        $this->assertEquals(1, $violation->getLine());
    }

    public function testIgnoresComments(): void
    {
        $content = '<?php
        // This is a comment with var_dump
        /* Another comment with exec */
        * var_dump in doc comment
        echo "Hello World";
        ?>';
        $file = $this->createTempFile('test.php', $content);

        $result = $this->linter->lint($file);

        $this->assertCount(0, $result->getViolations());
    }

    public function testDetectsMultipleViolations(): void
    {
        $content = '<?php
        var_dump($data);
        print_r($array);
        ?>';
        $file = $this->createTempFile('test.php', $content);

        $result = $this->linter->lint($file);

        $this->assertCount(2, $result->getViolations());

        $functions = array_map(function (SecurityViolation $v) {
            return $v->getFunction();
        }, $result->getViolations());

        $this->assertContains('var_dump', $functions);
        $this->assertContains('print_r', $functions);
    }

    public function testCustomInsecureFunction(): void
    {
        $this->linter->addInsecureFunction('my_debug', 'Custom debug function');

        $content = '<?php my_debug($data); ?>';
        $file    = $this->createTempFile('test.php', $content);

        $result = $this->linter->lint($file);

        $this->assertCount(1, $result->getViolations());
        $violation = $result->getViolations()[0];
        $this->assertEquals('my_debug', $violation->getFunction());
        $this->assertEquals('Custom debug function', $violation->getReason());
    }

    public function testLintDirectory(): void
    {
        $this->createTempFile('file1.php', '<?php var_dump($data); ?>');
        $this->createTempFile('file2.php', '<?php print_r($data); ?>');
        $this->createTempFile('file3.php', '<?php echo "clean file"; ?>');

        $result = $this->linter->lint($this->tempDir);

        $this->assertCount(2, $result->getViolations());
        $this->assertCount(2, $result->getFilesWithViolations());
    }

    public function testExcludePatterns(): void
    {
        // Create subdirectories
        mkdir($this->tempDir . '/vendor', 0777, true);
        mkdir($this->tempDir . '/src', 0777, true);

        $this->createTempFile('vendor/test.php', '<?php var_dump($data); ?>');
        $this->createTempFile('src/test.php', '<?php var_dump($data); ?>');

        // Use the correct pattern format for Symfony Finder
        $this->linter->setExcludePatterns(['vendor']);
        $result = $this->linter->lint($this->tempDir);

        // Should only find violation in src/, not in vendor/
        $this->assertCount(1, $result->getViolations());
        $this->assertStringContainsString('src/test.php', $result->getViolations()[0]->getFile());
    }

    public function testNonExistentPath(): void
    {
        $result = $this->linter->lint('/non/existent/path');

        $this->assertGreaterThan(0, $result->getErrorCount());
        $this->assertStringContainsString('not found', $result->getErrors()[0]);
    }

    public function testSecurityViolationSeverity(): void
    {
        $violation = new SecurityViolation(
            '/test.php',
            1,
            1,
            'eval',
            'Test reason',
            'eval($code)'
        );

        $this->assertEquals('high', $violation->getSeverity());

        $violation2 = new SecurityViolation(
            '/test.php',
            1,
            1,
            'var_dump',
            'Test reason',
            'var_dump($data)'
        );

        $this->assertEquals('medium', $violation2->getSeverity());
    }

    public function testViolationToArray(): void
    {
        $violation = new SecurityViolation(
            '/test.php',
            10,
            5,
            'eval',
            'Code evaluation function',
            'eval($code)'
        );

        $array = $violation->toArray();

        $this->assertEquals('/test.php', $array['file']);
        $this->assertEquals(10, $array['line']);
        $this->assertEquals(5, $array['column']);
        $this->assertEquals('eval', $array['function']);
        $this->assertEquals('Code evaluation function', $array['reason']);
        $this->assertEquals('eval($code)', $array['context']);
        $this->assertEquals('high', $array['severity']);
    }

    private function createTempFile(string $name, string $content): string
    {
        $filePath = $this->tempDir . '/' . $name;
        $dir      = dirname($filePath);

        if (! is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents($filePath, $content);
        return $filePath;
    }

    private function removeDirectory(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }
}
