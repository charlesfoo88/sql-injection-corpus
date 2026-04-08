# Reproduce Results Instructions

**MDAI Industry Project**: Human & Neuro-Symbolic AI Remediation for Python SQL Injection

This guide explains how to independently verify the test results for the SQL injection corpus samples. Follow these instructions step-by-step to set up your environment and run the tests.

---

## Quick Overview

**What you'll do**:
1. Get the corpus from GitHub (clone or download)
2. Verify Python is installed
3. **(Optional)** Install PostgreSQL (only for P5 samples)
4. Set up a Python environment
5. Install dependencies (psycopg2-binary, Django)
6. Run tests on sample vulnerabilities
7. Review test results

**Time required**: ~15-30 minutes (SQLite samples) or ~30-45 minutes (with PostgreSQL for P5)  
**Prerequisites**: Basic command-line knowledge

**Database Requirements**:
- **P4, P6, P9 samples**: SQLite (built into Python - no installation needed)
- **P5 samples**: PostgreSQL server (installation required - see Step 1.5)

---

## Step 0: Get the Corpus from GitHub

### Option A: Clone with Git (Recommended)

**First, check if you have Git installed**:
```bash
git --version
# Should show: git version x.x.x
# If not installed, go to: https://git-scm.com/downloads
```

**Clone the repository**:
```bash
# Navigate to where you want to store the corpus
cd Documents
# Or anywhere you prefer, like: cd Desktop

# Clone the repository
git clone https://github.com/charlesfoo88/sql-injection-corpus.git

# Navigate into the cloned folder
cd sql-injection-corpus

# Verify you're in the right place
ls
# You should see: README.md, requirements.txt, P4_WHERE_MULTI_01_MEDIUM/, etc.
```

**Note**: The folder will be named `sql-injection-corpus` (with hyphens) after cloning.

### Option B: Download as ZIP (If you don't have Git)

1. **Go to the GitHub repository** in your web browser
   - URL: `https://github.com/charlesfoo88/sql-injection-corpus`

2. **Download the repository**:
   - Click the green **"Code"** button
   - Select **"Download ZIP"**
   - Save the ZIP file to your computer

3. **Extract the ZIP file**:
   - **Windows**: Right-click → "Extract All..." → Choose location
   - **Mac**: Double-click the ZIP file
   - **Linux**: `unzip sql-injection-corpus-main.zip`

4. **Navigate to the extracted folder**:
   ```bash
   cd path/to/sql-injection-corpus-main
   # Or whatever the extracted folder is named
   
   # Verify you're in the right place
   ls
   # Should see: README.md, requirements.txt, P4_WHERE_MULTI_01_MEDIUM/, etc.
   ```

**Note**: If you download as ZIP, the folder name might be `sql-injection-corpus-main` instead of `sql_injection_corpus`. That's fine - just use that name in the commands below.

---

## Step 1: Verify Your Setup

### What You Need
- Windows, Linux, or macOS computer
- Python 3.8 or newer installed
- Terminal access (PowerShell on Windows, Terminal on Mac/Linux)
- The `sql_injection_corpus` folder (this folder containing this file)

### Verify Your Setup

**Check Python version**:
```bash
python --version
# Should show: Python 3.8.x or higher
# If not found, try: python3 --version
```

**Check your current location**:
```bash
# Windows PowerShell
pwd
# Should show something like: C:\...\sql_injection_corpus

# Mac/Linux
pwd
# Should show something like: /home/.../sql_injection_corpus
```

**Important**: Make sure you're in the `sql_injection_corpus` folder (the one that contains this file). If not:
```bash
# Navigate to it, for example:
cd "path/to/sql_injection_corpus"
```

---

## Step 1: Verify Your Setup

### What You Need
- Windows, Linux, or macOS computer
- Python 3.8 or newer installed
- Terminal access (PowerShell on Windows, Terminal on Mac/Linux)
- The corpus folder (downloaded/cloned in Step 0)

### Verify Python and Location

**Check Python version**:
```bash
python --version
# Should show: Python 3.8.x or higher
# If not found, try: python3 --version
```

**If Python is not installed**:
- **Windows**: Download from https://www.python.org/downloads/
- **Mac**: Use Homebrew: `brew install python3` or download from python.org
- **Linux**: `sudo apt install python3 python3-pip` (Ubuntu/Debian)

**Check your current location**:
```bash
# Windows PowerShell or Mac/Linux Terminal
pwd
# Should show something like: C:\...\sql-injection-corpus
# Or: /home/.../sql-injection-corpus
```

**Important**: Make sure you're in the corpus folder (the one from GitHub that contains this file). If not:
```bash
# Navigate to it, for example:
cd path/to/sql-injection-corpus
```

---

## Step 1.5: Database Setup (Optional - P5 Samples Only)

**Do you need this step?**
- ✅ **Skip this if testing P4, P6, or P9 samples** - SQLite is built into Python
- ⚠️ **Required only for P5 samples** (P5_DYNAMIC_IDENTIFIERS_01_MEDIUM, P5_DYNAMIC_IDENTIFIERS_02_HARD)

### Install PostgreSQL Server (P5 Samples Only)

**Windows**:
1. Download PostgreSQL from: https://www.postgresql.org/download/windows/
2. Run the installer (use default port 5432)
3. Set password to `postgres123` when prompted (or remember your password)
4. After installation, verify:
   ```powershell
   # Check if PostgreSQL service is running
   Get-Service -Name postgresql*
   ```

**Mac**:
```bash
# Install via Homebrew
brew install postgresql@14

# Start PostgreSQL service
brew services start postgresql@14

# Create default user with password
psql postgres -c "ALTER USER postgres PASSWORD 'postgres123';"
```

**Linux (Ubuntu/Debian)**:
```bash
# Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Set password for postgres user
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'postgres123';"
```

**Verify PostgreSQL is running**:
```bash
# Try connecting (should succeed without errors)
psql -U postgres -h localhost -p 5432
# Enter password: postgres123
# Then type: \q to quit
```

**Note**: If you use a different password, you'll need to update connection parameters in P5 test files.

---

## Step 2: Set Up Python Environment

Choose ONE of the following options based on what you have installed:

### Option A: Create New Conda Environment (Recommended if you have Anaconda/Miniconda)

**First, check if you have conda**:
```bash
conda --version
# Should show: conda x.x.x
# If you get an error, skip to Option B
```

**Create and activate environment**:
```bash
# Create new environment
conda create -n sqli_corpus python=3.10 -y

# Activate environment
conda activate sqli_corpus

# Your prompt should now show: (sqli_corpus)

# Install dependencies
pip install psycopg2-binary Django
```

### Option B: Create New Virtual Environment (If you don't have Conda)

**Windows**:
```powershell
# Create virtual environment
python -m venv sqli_env

# Activate environment
sqli_env\Scripts\activate

# Your prompt should now show: (sqli_env)

# Install dependencies
pip install -r requirements.txt
```

**Mac/Linux**:
```bash
# Create virtual environment
python3 -m venv sqli_env

# Activate environment
source sqli_env/bin/activate

# Your prompt should now show: (sqli_env)

# Install dependencies
pip install -r requirements.txt
```

### Option C: Use Existing Environment (Quick but not recommended)

```bash
# Just install the required packages into your current environment
pip install psycopg2-binary Django
```

---

## Step 3: Verify Installation

**Check that packages are installed**:
```bash
pip list | grep -E "psycopg2|Django"
# Should show:
# Django         4.x.x (or higher)
# psycopg2-binary 2.x.x (or higher)
```

**Windows PowerShell alternative**:
```powershell
pip list | Select-String "psycopg2|Django"
```

✅ **If you see both packages listed, setup is complete!**

---

## Step 4: Run Your First Test (Quick Verification)

Let's start with the easiest sample to verify everything works.

### Navigate to P4 Sample (Recommended First Test)
```bash
# From sql_injection_corpus folder, go into P4 sample
cd P4_WHERE_MULTI_01_MEDIUM

# Verify you're in the right place - you should see run_all_tests.ps1
ls
# or on Windows: dir
```

### Run Automated Tests

**Windows (PowerShell)**:
```powershell
.\run_all_tests.ps1
```

**If you get execution policy error on Windows**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then try again:
.\run_all_tests.ps1
```

**Mac/Linux (Alternative - run manually)**:
```bash
# Initialize database
python P4_01_where_multiple.py

# Test Claude
python P4_01_automated_test.py --llm claude > test_outputs/test_functional_exploit_claude.txt 2>&1

# Test ChatGPT
python P4_01_automated_test.py --llm chatgpt > test_outputs/test_functional_exploit_chatgpt.txt 2>&1

# Test Gemini
python P4_01_automated_test.py --llm gemini > test_outputs/test_functional_exploit_gemini.txt 2>&1

echo "Tests complete! Results saved in test_outputs/"
```

---

## Understanding Your Results

After running tests, you'll see results in the `test_outputs/` folder.

### Check Test Results

```bash
# List all result files
ls test_outputs/
# You should see:
# test_functional_exploit_claude.txt
# test_functional_exploit_chatgpt.txt
# test_functional_exploit_gemini.txt
```

### View Individual Results

**Windows**:
```powershell
# View Claude's results
Get-Content test_outputs\test_functional_exploit_claude.txt | more
```

**Mac/Linux**:
```bash
# View Claude's results
cat test_outputs/test_functional_exploit_claude.txt | less
# Press 'q' to quit
```

### Quick Summary Check

Look for these indicators in the test output:

✅ **PASSED** - Test succeeded  
❌ **FAILED** - Test failed  
🔒 **BLOCKED** - Security test passed (exploit was blocked)  
⚠️ **EXPLOIT SUCCESSFUL** - Vulnerability demonstrated (expected in exploit tests)

---

## Prerequisites

---

## Testing Other Samples

Once P4_WHERE_MULTI_01_MEDIUM works, you can test other samples the same way.

### Sample Directory Reference

From the `sql_injection_corpus` folder:

```bash
# Go back to corpus root (if you're still in P4 folder)
cd ..

# Test other samples:
cd P5_DYNAMIC_IDENTIFIERS_01_MEDIUM
cd P5_DYNAMIC_IDENTIFIERS_02_HARD
cd P6_ORM_01_MEDIUM
cd P6_ORM_02_HARD
cd P9_SECOND_ORDER_01_VERY_HARD
```

### All Available Samples

| Folder Name | Difficulty | Database | Installation Needed? | LLM Success | Best For |
|-------------|------------|----------|---------------------|-------------|----------|
| **P4_WHERE_MULTI_01_MEDIUM** | Medium | SQLite | ✅ **No** (built-in) | 3/3 (100%) | **Start here - easiest** |
| P5_DYNAMIC_IDENTIFIERS_01_MEDIUM | Medium | PostgreSQL | ❌ **Yes** (server) | 2/3 (67%) | Dynamic identifiers |
| P5_DYNAMIC_IDENTIFIERS_02_HARD | Hard | PostgreSQL | ❌ **Yes** (server) | 0/3 (0%) | Complex injection |
| P6_ORM_01_MEDIUM | Medium | SQLite | ✅ **No** (built-in) | 2/3 (67%) | Django ORM |
| P6_ORM_02_HARD | Hard | SQLite | ✅ **No** (built-in) | 0/3 (0%) | Complex ORM |
| P9_SECOND_ORDER_01_VERY_HARD | Very Hard | SQLite | ✅ **No** (built-in) | 0/3 (0%) | Second-order SQLi |

**Database Requirements Summary**:
- **SQLite samples (P4, P6, P9)**: No installation needed - sqlite3 module is built into Python
- **PostgreSQL samples (P5)**: Requires PostgreSQL server installation (see Step 1.5)

---

## Manual Testing (Alternative to Automated Runner)

If the PowerShell script doesn't work or you want more control:

### Quick Test Flow (Any Sample)

**From inside a sample folder** (e.g., P4_WHERE_MULTI_01_MEDIUM):

1. **Run the exploit** (shows vulnerability exists):
   ```bash
   python P4_01_exploit.py
   ```
   
   **What you'll see**: Attack demonstrations with payloads and stolen data

2. **Run functional test** (shows secure version works):
   ```bash
   python P4_01_functional_test.py
   ```
   
   **What you'll see**: Test results showing attacks are blocked

3. **Test an LLM's fix**:
   ```bash
   python P4_01_automated_test.py --llm claude
   ```
   
   **What you'll see**: Detailed test results for Claude's remediation

---

## Understanding Test Output Files

After running tests, each sample folder will have:

### Folder Structure After Testing
```
P4_WHERE_MULTI_01_MEDIUM/
├── test_outputs/                          ← TEST RESULTS HERE
│   ├── test_functional_exploit_claude.txt    ← Claude's test log
│   ├── test_functional_exploit_chatgpt.txt   ← ChatGPT's test log
│   └── test_functional_exploit_gemini.txt    ← Gemini's test log
├── P4_01_llm_test_results.md             ← Analysis report (pre-existing)
└── ... (other files)
```

### Reading Test Logs

**Each test log contains**:
1. **Functional Tests** - Do legitimate operations work?
2. **Exploit Tests** - Are attacks properly blocked?
3. **Pass/Fail Summary** - Overall results

**Example output snippet**:
```
[Functional Test 1/8] Testing legitimate table access...
✓ PASSED: get_products() returned 6 records

[Security Test 1/6] Testing UNION injection...
✓ BLOCKED: Malicious payload 'products UNION SELECT password FROM users' was rejected

SUMMARY: 14/14 tests passed
RESULT: ✅ Production Ready
```

### Checking Analysis Reports

Open `P#_##_llm_test_results.md` in each folder to see comprehensive analysis with:
- Executive summary
- Test summary table
- Detailed LLM evaluation
- Production readiness assessment

---

## Complete Testing Workflow Example

**Full walkthrough for beginners**:

```bash
# Step 0: Get the corpus from GitHub
git clone https://github.com/charlesfoo88/sql-injection-corpus.git
cd sql-injection-corpus

# Step 1: Verify Python and location
python --version  # Should show 3.8+
pwd              # Verify you're in sql-injection-corpus folder

# Step 1.5: (OPTIONAL) Install PostgreSQL - only if testing P5 samples
# See "Step 1.5: Database Setup" section above for platform-specific instructions
# SQLite samples (P4, P6, P9) don't need this - skip to Step 2

# Step 2: Create and activate environment (using conda example)
conda create -n sqli_corpus python=3.10 -y
conda activate sqli_corpus
pip install psycopg2-binary Django

# Step 3: Verify installation
pip list | grep -E "psycopg2|Django"

# Step 4: Run first test (P4 uses SQLite - no database server needed)
cd P4_WHERE_MULTI_01_MEDIUM
.\run_all_tests.ps1  # Windows
# Or for Mac/Linux: python P4_01_automated_test.py --llm claude

# Step 5: Check results
ls test_outputs/
# Should see 3 .txt files

# Step 6: View Claude's results
cat test_outputs/test_functional_exploit_claude.txt
# (or use 'Get-Content' on Windows)

# Step 7: Read analysis report
# Open P4_01_llm_test_results.md in a text editor

# Step 8: Go back and test another sample
cd ..
cd P5_DYNAMIC_IDENTIFIERS_01_MEDIUM
.\run_all_tests.ps1
```

---

## Troubleshooting Common Issues

### Issue: `python: command not found`
**Fix**: 
```bash
# Try python3 instead
python3 --version

# If that works, use python3 for all commands
python3 P4_01_exploit.py
```

### Issue: `ModuleNotFoundError: No module named 'psycopg2'`
**Cause**: PostgreSQL adapter not installed (needed for P5 samples)  
**Fix**: 
```bash
pip install psycopg2-binary
```

### Issue: `ModuleNotFoundError: No module named 'django'`
**Cause**: Django not installed (needed for P6 samples)  
**Fix**: 
```bash
pip install Django
```

### Issue: PowerShell script won't run
**Error**: `cannot be loaded because running scripts is disabled`  
**Fix**: 
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then try running the script again
```

### Issue: `Database is locked` or test database already exists
**Cause**: Previous test run didn't clean up properly  
**Fix**: 
```bash
# Delete test databases
rm test_*.db
rm test_outputs/test_*.db
# Or on Windows:
del test_*.db
del test_outputs\test_*.db
```

### Issue: Tests fail with import errors
**Error**: `No module named 'P5_01_dynamic_identifiers'`  
**Cause**: Running from wrong directory  
**Fix**: Make sure you're in the sample folder (e.g., `P5_DYNAMIC_IDENTIFIERS_01_MEDIUM/`), not in subdirectories

### Issue: `Permission denied` when creating files
**Cause**: Insufficient permissions or files are locked  
**Fix**: 
- Close any text editors that have test output files open
- Run terminal as administrator (Windows) or use `sudo` (Mac/Linux) if needed

### Issue: Test outputs show `0/0 tests passed`
**Cause**: LLM extracted code might not exist  
**Fix**: Check if `llm_extracted/` folders exist and contain Python files. Some samples may not have all 3 LLM implementations.

### Issue: PostgreSQL connection errors (P5 samples)
**Error**: `psycopg2.OperationalError: could not connect to server`  
**Cause**: PostgreSQL server not installed or not running  
**Fix**: 
1. Install PostgreSQL server (see Step 1.5)
2. Verify service is running:
   - **Windows**: Check Services app for "postgresql" service
   - **Mac**: `brew services list | grep postgresql`
   - **Linux**: `sudo systemctl status postgresql`
3. Verify connection: `psql -U postgres -h localhost -p 5432`

**Note**: P4, P6, and P9 samples use SQLite and don't need PostgreSQL.

---

## Platform-Specific Notes

### Windows Users
- Use PowerShell (not Command Prompt) for best compatibility
- Use backslashes in paths: `test_outputs\test_claude.txt`
- PowerShell script: `.\run_all_tests.ps1` works best

### Mac/Linux Users  
- Use forward slashes in paths: `test_outputs/test_claude.txt`
- PowerShell scripts won't work - use manual testing method instead
- May need to use `python3` instead of `python`

### All Platforms
- **SQLite samples (P4, P6, P9)**: Work out-of-box, no database installation needed
- **PostgreSQL samples (P5)**: Require PostgreSQL server installation and configuration
- If testing only SQLite samples, skip PostgreSQL installation entirely

---

## Verification Checklist

Use this to ensure complete verification:

- [ ] Python 3.8+ installed and verified (`python --version`)
- [ ] Located in `sql_injection_corpus` folder (`pwd` shows correct path)
- [ ] Environment created and activated (prompt shows environment name)
- [ ] Dependencies installed (`pip list` shows psycopg2-binary and Django)
- [ ] **(P5 samples only)** PostgreSQL server installed and running
- [ ] P4_WHERE_MULTI_01_MEDIUM test runs successfully
- [ ] Test output files created in `test_outputs/` folder
- [ ] Can open and read test result files
- [ ] Analysis report (`P4_01_llm_test_results.md`) matches test results
- [ ] Successfully tested at least 2-3 different samples
- [ ] Understand how to interpret test results

---

## Quick Command Reference

**Common commands you'll use**:

```bash
# Navigate to corpus (after cloning from GitHub)
cd path/to/sql-injection-corpus

# Activate environment
conda activate sqli_corpus              # Conda
source sqli_env/bin/activate           # Linux/Mac venv
sqli_env\Scripts\activate              # Windows venv

# Enter sample folder
cd P4_WHERE_MULTI_01_MEDIUM

# Run automated tests
.\run_all_tests.ps1                    # Windows
python P4_01_automated_test.py --llm claude  # Manual

# View results
cat test_outputs/test_functional_exploit_claude.txt    # Linux/Mac
Get-Content test_outputs\test_functional_exploit_claude.txt  # Windows

# Go back to corpus root
cd ..

# Deactivate environment when done
conda deactivate                       # Conda
deactivate                             # venv
```

---

## Need Help?

If you encounter issues not covered here:

1. **Check `P#_##_metadata.json`** in each sample folder for sample-specific requirements
2. **Review `P#_##_llm_test_results.md`** for expected test behavior
3. **Examine test logs** in `test_outputs/` for detailed error messages
4. **Verify dependencies**: `pip list | grep -E "(psycopg2|Django)"`
5. **Check Python version**: Must be 3.8 or higher
6. **Ensure correct directory**: You must be inside a sample folder to run tests

---

**Last Updated**: April 8, 2026  
**Tested On**: Python 3.10+, Windows 11, Ubuntu 22.04, macOS Monterey  
**Database Requirements**: SQLite (built-in), PostgreSQL 14+ (P5 samples only)  
**Support**: See README.md for corpus structure documentation
