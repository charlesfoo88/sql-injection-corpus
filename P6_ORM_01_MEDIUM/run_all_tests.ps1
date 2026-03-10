# P6_01 Automated Test Runner
# Runs tests for all LLM implementations and saves results

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "P6_01 AUTOMATED TEST RUNNER" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

# Use mdai conda environment Python
$python = "C:\Users\charlesfoo\anaconda3\envs\mdai\python.exe"

$llms = @('claude', 'chatgpt', 'gemini')
$test_outputs = @()

foreach ($llm in $llms) {
    Write-Host "Testing $llm implementation..." -ForegroundColor Yellow
    
    $output_file = "test_outputs/test_functional_exploit_$llm.txt"
    
    # Run test and capture output
    & $python P6_01_automated_test.py $llm | Tee-Object -FilePath $output_file
    
    Write-Host ""
    Write-Host "Saved results to $output_file" -ForegroundColor Green
    Write-Host ""
    
    $test_outputs += $output_file
}

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "ALL TESTS COMPLETED" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test results saved to:" -ForegroundColor Green
foreach ($file in $test_outputs) {
    Write-Host "  - $file" -ForegroundColor White
}
Write-Host ""
