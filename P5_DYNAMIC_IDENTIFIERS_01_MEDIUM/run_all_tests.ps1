$env:Path += ";C:\Program Files\PostgreSQL\17\bin"
cd "c:\Users\charlesfoo\Documents\ML\MDAI Industry project\sql_injection_corpus\P5_DYNAMIC_IDENTIFIERS_01_MEDIUM"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "P5_01_MEDIUM Automated Test Runner" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Testing ChatGPT implementation..." -ForegroundColor Yellow
C:\Users\charlesfoo\anaconda3\envs\mdai\python.exe P5_01_automated_test.py chatgpt 2>&1 | Tee-Object -FilePath test_outputs/test_functional_exploit_chatgpt.txt

Write-Host "`n----------------------------------------`n" -ForegroundColor Gray

Write-Host "Testing Gemini implementation..." -ForegroundColor Yellow
C:\Users\charlesfoo\anaconda3\envs\mdai\python.exe P5_01_automated_test.py gemini 2>&1 | Tee-Object -FilePath test_outputs/test_functional_exploit_gemini.txt

Write-Host "`n----------------------------------------`n" -ForegroundColor Gray

Write-Host "Testing Claude implementation..." -ForegroundColor Yellow
C:\Users\charlesfoo\anaconda3\envs\mdai\python.exe P5_01_automated_test.py claude 2>&1 | Tee-Object -FilePath test_outputs/test_functional_exploit_claude.txt

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "All tests complete!" -ForegroundColor Green
Write-Host "Results saved to test_outputs/test_functional_exploit_*.txt files" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan
