# PowerShell test runner for P4_01_WHERE_MULTI_01_MEDIUM

Write-Host "=== P4_01 WHERE Multiple Conditions - LLM Test Runner ===" -ForegroundColor Cyan
Write-Host "Starting test execution: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Test database path
$TEST_DB = "test_p4_01.db"

# Initialize test database
Write-Host "[1/4] Initializing test database..." -ForegroundColor Yellow
python P4_01_where_multiple.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "Database initialization failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Database initialized`n" -ForegroundColor Green

# Test Claude implementation
Write-Host "[2/4] Testing Claude Sonnet 4.5 implementation..." -ForegroundColor Yellow
if (Test-Path "llm_extracted\claude_extracted\P4_01_where_multiple_secure.py") {
    python P4_01_automated_test.py --llm claude > test_outputs\test_functional_exploit_claude.txt 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Claude tests completed" -ForegroundColor Green
    } else {
        Write-Host "✗ Claude tests failed (see test_outputs\test_functional_exploit_claude.txt)" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Claude implementation not found (skipping)" -ForegroundColor DarkYellow
}
Write-Host ""

# Test ChatGPT implementation  
Write-Host "[3/4] Testing ChatGPT GPT-5.3 implementation..." -ForegroundColor Yellow
if (Test-Path "llm_extracted\chatgpt_extracted\P4_01_where_multiple_secure.py") {
    python P4_01_automated_test.py --llm chatgpt > test_outputs\test_functional_exploit_chatgpt.txt 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ ChatGPT tests completed" -ForegroundColor Green
    } else {
        Write-Host "✗ ChatGPT tests failed (see test_outputs\test_functional_exploit_chatgpt.txt)" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ ChatGPT implementation not found (skipping)" -ForegroundColor DarkYellow
}
Write-Host ""

# Test Gemini implementation
Write-Host "[4/4] Testing Gemini 3 implementation..." -ForegroundColor Yellow
if (Test-Path "llm_extracted\gemini_extracted\P4_01_where_multiple_secure.py") {
    python P4_01_automated_test.py --llm gemini > test_outputs\test_functional_exploit_gemini.txt 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Gemini tests completed" -ForegroundColor Green
    } else {
        Write-Host "✗ Gemini tests failed (see test_outputs\test_functional_exploit_gemini.txt)" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Gemini implementation not found (skipping)" -ForegroundColor DarkYellow
}
Write-Host ""

# Summary
Write-Host "=== Test Execution Complete ===" -ForegroundColor Cyan
Write-Host "Results saved in test_outputs\ directory" -ForegroundColor Gray
Write-Host "Review individual test logs for detailed results`n" -ForegroundColor Gray

# Cleanup
if (Test-Path $TEST_DB) {
    Write-Host "Cleaning up test database..." -ForegroundColor Gray
    Remove-Item $TEST_DB -Force
    Write-Host "✓ Cleanup complete" -ForegroundColor Green
}
