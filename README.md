# SQL Injection Corpus - User Guide

## Overview
This corpus contains SQL injection vulnerability samples for the MDAI Industry Project on "Human & Neuro-Symbolic AI Remediation for Python SQL Injection".

**Quick Navigation**:
- [Root Folder Files](#root-folder-files) - What's in the main directory
- [Sample Folder Structure](#sample-folder-structure) - What's inside each P#_## folder
- [How to Use This Corpus](#how-to-use-this-corpus) - Getting started
- [Understanding Test Results](#understanding-test-results) - Reading the analysis files

---

## Root Folder Files

When you open the `sql_injection_corpus/` folder, you'll see:

- **README.md** - This guide (explains corpus structure and usage)

### 📁 Sample Folders (The Main Content)

Each folder contains one complete vulnerability sample with all test files and results:

```
P5_DYNAMIC_IDENTIFIERS_01_MEDIUM/    ← Medium difficulty, first P5 pattern sample
P5_DYNAMIC_IDENTIFIERS_02_HARD/      ← Hard difficulty, second P5 pattern sample
P6_ORM_01_MEDIUM/                    ← Medium difficulty, first P6 pattern sample
P6_ORM_02_HARD/                      ← Hard difficulty, second P6 pattern sample
P9_SECOND_ORDER_01_VERY_HARD/        ← Very hard difficulty, first P9 pattern sample
```

**Naming Convention**: `P{pattern_number}_{pattern_name}_{sequence}_{difficulty}/`

---

## Sample Folder Structure

Each sample folder (e.g., `P5_DYNAMIC_IDENTIFIERS_01_MEDIUM/`) contains:

### 🔴 Core Vulnerability Files

| File Pattern | Example | Purpose |
|--------------|---------|---------|
| `P#_##_*.py` | `P5_01_dynamic_identifiers.py` | **Vulnerable code** - The actual buggy code with SQL injection |
| | | **Note:** P6 samples use multiple Django files (models.py, views.py, django_settings.py, query_builder.py, validators.py) instead of a single file |
| `P#_##_exploit.py` | `P5_01_exploit.py` | **Exploit proof** - Demonstrates the attack works |
| `P#_##_functional_test.py` | `P5_01_functional_test.py` | **Safe reference** - Shows correct implementation + tests |
| `P#_##_metadata.json` | `P5_01_metadata.json` | **Structured info** - Sample details, CWE, attack vectors |
| `P#_##_sqlite_test.py` | `P5_02_sqlite_test.py` | **Automated validation** - Security pattern testing (when available) |

### 📝 Prompt & Test Results

| File Pattern | Example | Purpose |
|--------------|---------|---------|
| `P#_##_COPY_THIS_PROMPT_MINIMAL.md` | `P5_01_COPY_THIS_PROMPT_MINIMAL.md` | **LLM prompt** - What to send to AI for remediation |
| `P#_##_llm_test_results.md` | `P5_01_llm_test_results.md` | **Comprehensive analysis** - All 3 LLM test results |

### 🤖 Runtime Testing Files

| File Pattern | Example | Purpose |
|--------------|---------|---------|
| `P#_##_automated_test.py` | `P5_01_automated_test.py` | **Automation script** - Runs all tests against LLM code |
| `run_all_tests.ps1` | `run_all_tests.ps1` | **PowerShell runner** - Executes all tests sequentially |
| `test_functional_exploit_<llm>.txt` | `test_functional_exploit_chatgpt.txt` | **Functional + Exploit test output** - Individual LLM test logs (both functional and security tests) |

### 📦 LLM Response Files (Original Outputs)

| File Pattern | Source | Format |
|--------------|--------|--------|
| `claude P#_##.zip` | Claude Sonnet 4.5 output | ZIP with code files |
| `ChatGpt P#_##.htm` or `OpenAI P#_##.htm` | ChatGPT GPT-5.3 output | HTML/Word document |
| `google p#_##.htm` or `Google_P#_##.docx` | Gemini 3 output | HTML/Word document |
| `<LLM> P#_##.files/` | HTML support folders | Assets for HTML files (ignore) |

### 🔧 Extracted LLM Code

| File Pattern | Source | Purpose |
|--------------|--------|---------|
| `claude_extracted/` | Claude ZIP extraction | Directory with Claude's .py files |
| `chatgpt_extracted/` | ChatGPT HTML/Word extraction | Directory with ChatGPT's .py files |
| `gemini_extracted/` | Gemini HTML/Word extraction | Directory with Gemini's .py files |

### 🎯 Sample Folder Example (P5_01 - Organized Standard Structure)

```
P5_DYNAMIC_IDENTIFIERS_01_MEDIUM/
│
├── Core Sample Files (Root - 11 files)
├── P5_01_dynamic_identifiers.py              ← Vulnerable code
├── P5_01_exploit.py                          ← Proof of exploitation
├── P5_01_functional_test.py                  ← Secure reference + tests
├── P5_01_metadata.json                       ← Structured documentation
├── P5_01_sqlite_test.py                      ← Automated validation
├── P5_01_COPY_THIS_PROMPT_MINIMAL.md        ← Prompt for LLMs
├── P5_01_llm_test_results.md                ← Complete analysis (Claude/ChatGPT/Gemini)
├── P5_01_automated_test.py                   ← Automation script
├── run_all_tests.ps1                         ← PowerShell runner
│
├── llm_responses/                            ← Original LLM outputs (7 items)
│   ├── Claude P5_01.zip                      ← Claude's response ZIP
│   ├── OpenAI P5_01.docx                     ← ChatGPT's response (Word)
│   ├── OpenAI P5_01.htm                      ← ChatGPT's response (HTML)
│   ├── OpenAI P5_01.files/                   ← HTML assets (ignore)
│   ├── Google_P5_01.docx                     ← Gemini's response (Word)
│   ├── Google_P5_01.htm                      ← Gemini's response (HTML)
│   └── Google_P5_01.files/                   ← HTML assets (ignore)
│
├── llm_extracted/                            ← Extracted LLM code (3 folders)
│   ├── claude_extracted/                     ← Extracted Claude .py files
│   ├── chatgpt_extracted/                    ← Extracted ChatGPT .py files
│   └── gemini_extracted/                     ← Extracted Gemini .py files
│
├── test_outputs/                             ← Test execution logs (3-4 files)
│   ├── test_functional_exploit_claude.txt    ← Claude functional + exploit test log
│   ├── test_functional_exploit_chatgpt.txt   ← ChatGPT functional + exploit test log
│   ├── test_functional_exploit_gemini.txt    ← Gemini functional + exploit test log
│   └── test_p5_01.db (if present)            ← SQLite test database (P6 samples only)
│
└── __pycache__/                              ← Python cache (ignore)
```

**Organizational Benefits**:
- **Root level** (11 files): Essential research files - easy to navigate and understand
- **llm_responses/**: Original outputs preserved for reference
- **llm_extracted/**: Ready-to-test code isolated from raw responses
- **test_outputs/**: All test logs organized separately from source

### 🎯 Sample Folder Example (P6_02 - Django Multi-File Structure)

```
P6_ORM_02_HARD/
│
├── Core Sample Files (Root - 16 files)
├── django_settings.py                        ← Django configuration (vulnerable file)
├── models.py                                 ← Django models (vulnerable file)
├── query_builder.py                          ← Query builder (vulnerable file)
├── validators.py                             ← Validators (vulnerable file)
├── views.py                                  ← View handlers (vulnerable file)
├── P6_02_exploit.py                          ← Proof of exploitation
├── P6_02_functional_test.py                  ← Secure reference + tests
├── P6_02_automated_test.py                   ← Automation script
├── P6_02_metadata.json                       ← Structured documentation
├── P6_02_COPY_THIS_PROMPT_MINIMAL.md        ← Prompt for LLMs
├── P6_02_llm_test_results.md                ← Complete analysis (Claude/ChatGPT/Gemini)
├── run_all_tests.ps1                         ← PowerShell runner
│
├── llm_responses/                            ← Original LLM outputs
├── llm_extracted/                            ← Extracted LLM code (3 folders)
├── test_outputs/                             ← Test execution logs (4 files)
│   ├── test_functional_exploit_*.txt (3)     ← Test logs for each LLM
│   └── test_p6_02.db                         ← SQLite test database (artifact)
└── __pycache__/                              ← Python cache (ignore)
```

**Key Differences from P5:**
- **Multiple vulnerable code files** (5 Django files) instead of single `P#_##_*.py`
- Django-specific files: `models.py`, `views.py`, `django_settings.py`, `query_builder.py`, `validators.py`
- Test database artifact: `test_p6_02.db` stored in `test_outputs/` (generated during testing)
- All other structure identical: `llm_responses/`, `llm_extracted/`, `test_outputs/` folders present

**Note on Architecture Variations**: 
- **P5 samples** (Dynamic Identifiers): Single vulnerable code file (e.g., `P5_01_dynamic_identifiers.py`)
- **P6 samples** (ORM): Multiple Django application files instead of single vulnerable code file:
  - `models.py` - Django models with vulnerable queries
  - `views.py` - View handlers with injection points
  - `django_settings.py` - Django configuration
  - `query_builder.py` - Query building logic (P6_02 only)
  - `validators.py` - Validation logic (P6_02 only)
  - This multi-file structure reflects realistic Django application architecture
- **P9 samples** (Second-Order): Use directory structure (api/, models/, services/) for multi-tier application
- **P5 samples (P5_01 and P5_02) use the standardized folder structure** - All LLMs in separate folders, consistent naming

---

## Understanding Test Results

Each `P#_##_llm_test_results.md` file contains:

### 📊 Executive Summary (Top Section)

```markdown
## 🚨 Executive Summary

**Critical Finding**: P5_01 achieved 100% production-ready rate (3/3 LLMs)

### Test Summary Table
| LLM | Version | CoT - Injection Points | CoT - Fix Approach | Functional Test | Exploit Test | Production Ready | Notes |
```

**What to look for:**
- **CoT - Injection Points** column: Percentage of injection points identified in analysis
- **CoT - Fix Approach** column: Whether LLM proposed the correct fix strategy
- **Production Ready** column: ✅ YES = safe to deploy, ❌ NO = needs fixes
- **Notes**: Key issues, compatibility concerns, or partial implementation details

### 📈 Detailed Sections

1. **About Section** - Overview of the specific vulnerability sample
2. **Executive Summary** - Quick results with Test Summary Table and Metrics Interpretation
3. **Key Observations** - Critical patterns and findings across all LLMs
4. **Human Review Required** - Routing decisions and remediation guidance if LLMs failed
5. **Runtime Test Evidence** - Actual execution results verifying vulnerability and fixes
6. **Test Configuration** - Runtime test setup and environment details
7. **Vulnerable Code Analysis** - Detailed breakdown of injection points and required fixes
8. **Appendix: Individual LLM Analysis** - Detailed Claude, ChatGPT, Gemini analysis

### 🎯 Quick Assessment

Look at the **Test Summary Table**:
- **All ✅ YES**: LLMs handle this pattern well
- **Mix of ✅/❌**: Some LLMs struggle
- **All ❌ NO**: Difficult pattern for current LLMs

---

---

## Detailed File Descriptions

### 📄 Vulnerable Code File (`P#_##_*.py`)
**Purpose**: The actual vulnerable code with SQL injection

**What it does**:
- Real Python code that could appear in production applications
- Contains intentional SQL injection vulnerability
- Includes detailed comments explaining:
  - Why the code is vulnerable
  - What the dangerous patterns are
  - Where the injection points are located
  - How an attacker would exploit it

**Example**: `P5_01_dynamic_identifiers.py`
```python
# VULNERABLE: Direct f-string interpolation of user input
query = f"SELECT * FROM {table_name}"  # ← Injection point
cursor.execute(query)
```

**Usage**: 
- This is what you'd send to an LLM for remediation
- This is what security scanners should detect
- This represents real-world vulnerable code

---

### 🔴 Exploit File (`P#_##_exploit.py`)
**Purpose**: Demonstrates the vulnerability is exploitable

**What it does**:
- Sets up a test database with sample data
- Executes actual attacks against the vulnerable code
- Shows exactly what an attacker can do:
  - Extract sensitive data (passwords, secrets)
  - Modify/delete data (DROP TABLE)
  - Discover database structure
- Prints detailed step-by-step attack breakdown
- Includes educational comments explaining each attack vector

**Example Output**:
```
⚠️ EXPLOIT SUCCESSFUL! Retrieved data:
  {'username': 'admin', 'password': 'supersecret123'}
  ↑ Admin passwords exposed!
```

**Usage**:
- Run this to verify the vulnerability exists
- Understand HOW the attack works
- See the real-world impact
- Educational demonstration of attack techniques

**How to run**:
```powershell
C:/Users/charlesfoo/anaconda3/Scripts/conda.exe run -n mdai python P5_01_exploit.py
```

---

### ✅ Functional Test File (`P#_##_functional_test.py`)
**Purpose**: Secure reference implementation with tests

**What it does**:
- Contains a SECURE reference implementation
- Shows the correct way to handle the vulnerability
- Includes test cases that verify:
  - Legitimate use cases still work
  - Malicious inputs are rejected
  - No information disclosure in errors
  - Security controls are effective
- Demonstrates the remediation technique

**Example Secure Code**:
```python
# SECURE: Whitelist validation BEFORE query construction
ALLOWED_TABLES = {'users', 'products'}
if table_name not in ALLOWED_TABLES:
    raise ValueError("Invalid table")
query = f"SELECT * FROM {table_name}"  # Now safe!
```

**Usage**:
- Compare vulnerable vs. secure implementations
- Validate that LLM-proposed fixes meet requirements
- Test that remediation works correctly
- Educational reference for safe coding patterns

**How to run**:
```powershell
C:/Users/charlesfoo/anaconda3/Scripts/conda.exe run -n mdai python P5_01_functional_test.py
```

---

### 📋 Metadata File (`P#_##_metadata.json`)
**Purpose**: Structured information about the vulnerability

**What it contains**:
```json
{
  "sample_id": "P5_01",
  "pattern_type": "P5",
  "pattern_name": "Dynamic Identifiers",
  "complexity": "Moderate",
  "cwe_id": "CWE-89",
  
  "vulnerability_details": {
    "injection_point": "table_name parameter",
    "root_cause": "No whitelist validation",
    "exploitability": "High"
  },
  
  "attack_vectors": [
    {
      "type": "UNION-based injection",
      "payload": "users UNION SELECT password FROM admin --",
      "impact": "Unauthorized data disclosure"
    }
  ],
  
  "remediation_requirements": {
    "primary_fix": "Whitelist validation",
    "safe_example": "if table_name not in ALLOWED: raise Error"
  },
  
  "educational_notes": {
    "for_non_security_experts": [
      "Think of table names like addresses - can't use ? placeholders",
      "Whitelist = guest list - only approved names allowed",
      "Attacker 'breaks out' by adding WHERE, UNION, etc."
    ]
  }
}
```

**Usage**:
- Quick reference for vulnerability characteristics
- Input for automated analysis tools
- Documentation for non-security experts
- Tracking complexity levels and CWE mappings

### 📝 Prompt File (`P#_##_COPY_THIS_PROMPT_MINIMAL.md`)
**Purpose**: Prompt to send to LLMs for remediation testing

**What it contains**:
- Minimal prompt asking for security analysis
- No hints about the vulnerability type
- Used to test LLM's ability to find and fix injection points

### 📊 Test Results File (`P#_##_llm_test_results.md`)
**Purpose**: Comprehensive analysis of LLM performance

**What it contains**:
- About section with vulnerability overview
- Executive summary with Test Summary Table and Metrics Interpretation
- Key observations and patterns across all LLMs
- Human review required (routing decisions and remediation guidance)
- Runtime test evidence (actual execution verification)
- Test configuration details
- Vulnerable code analysis (injection points and required fixes)
- Appendix with detailed analysis for Claude, ChatGPT, Gemini
- Production readiness assessment

---

**Last Updated**: March 11, 2026  
**Corpus Status**: 5 samples tested and documented
