# P6_ORM_02_HARD: LLM Test Results

**Status**: ✅ COMPLETE - All 3 LLMs tested with runtime validation  
**Test Date**: March 10, 2026  
**Test Type**: Single-shot, minimal prompts (no POC, no recommendations, no guiding questions)  
**Testing Protocol**: Separate conversations per sample, no contamination  
**Validation Method**: Runtime functional + exploit testing

**Testing Infrastructure**: Django + SQLite runtime tests with automated functional + exploit validation. Tests verify: (1) Functional correctness (API compatibility with original method signatures), (2) Injection blocking (all 10 attack vectors), (3) Security effectiveness.

---

## About P6_ORM_02_HARD

**Application**: Multi-Model Django Project Management System  
**Vulnerability**: Django ORM `.raw()`, `.extra()`, and `RawSQL()` SQL Injection (P6 Pattern) - 10 injection points  
**Architecture**: Multi-file system with 4 models, 8 views, query builder (850 lines)  
**False Security**: Validation decorators that check format but don't prevent SQL injection

**Test Methodology**:
- **Functional Tests (10 scenarios)**: Verify original API compatibility (method signatures, parameter types, return values)
- **Exploit Tests (10 attack vectors)**: Attempt SQL injection via WHERE (3), ORDER BY (2), GROUP BY (1), HAVING (2), SELECT (1), query builder chaining (1)
- **Production Ready Criteria**: Pass ALL functional tests + ALL exploit tests

---

## 🚨 Executive Summary

**Critical Finding**: P6_ORM_02_HARD reveals **systematic API compatibility failure across all 3 LLMs**

### Test Summary Table

| LLM | Version | CoT - Injection Points | CoT - Fix Approach | Functional Test | Exploit Test | Production Ready | Notes |
|-----|---------|------------------------|--------------------|-----------------|--------------| -----------------|-------|
| **Claude** | Sonnet 4.5 | 10/10 (100%) | ✅ CORRECT | ❌ FAIL (1/10, 10%) | ✅ PASS (10/10, 100%) | ❌ NO | Changed method parameters |
| **ChatGPT** | GPT-5.3 | 10/10 (100%) | ✅ CORRECT | ❌ FAIL (1/10, 10%) | ✅ PASS (10/10, 100%) | ❌ NO | Changed method parameters |
| **Gemini** | 3 | 10/10 (100%) | ✅ CORRECT | ❌ FAIL (1/10, 10%) | ✅ PASS (10/10, 100%) | ❌ NO | Changed method parameters |

**Remarkable Result**: ALL 3 LLMs produced **identical test outcomes** (1/10 functional, 10/10 security)

### Metrics Interpretation

| Metric | What It Measures | ✅ PASS | ❌ FAIL |
|--------|------------------|---------|---------|
| **CoT - Injection Points** | Analysis quality: Injection points identified / total | 10/10 (100%) | <10/10 (missed vulnerabilities) |
| **CoT - Fix Approach** | Solution correctness: Proper remediation method chosen | ✅ CORRECT (Django ORM or allowlists) | ❌ WRONG (manual escaping, validation-only) |
| **Functional Test** | API compatibility: Does code maintain existing method signatures? | 100% (drop-in replacement) | <100% (breaking API changes) |
| **Exploit Test** | Security effectiveness: % of injection points actually fixed | 100% (all patched) | <100% (≥1 unpatched = exploit possible) |
| **Production Ready** | Binary deployment decision: All metrics must pass | YES (all criteria met) | NO (any metric fails) |

**Key Principle**: Security alone isn't enough. The prompt constraint **"Maintain all existing functionality"** requires API-compatible drop-in replacement. Code must be both secure AND functionally compatible.

### Key Observations

#### Key Observation #1: Universal API Compatibility Failure - All 3 LLMs Produced Identical Breaking Changes

**The Result**: P6_ORM_02_HARD achieved **0% production-ready rate (0/3 LLMs)** - ALL THREE failed functional compatibility despite perfect security.

**What Happened**: ALL THREE LLMs demonstrated **exact same behavior**:

**Security**: ✅ 10/10 exploits blocked (100% perfect)
- All allowlists working correctly
- All parameterized queries effective
- Django ORM refactoring sound
- No SQL injection vectors remain

**Functional Compatibility**: ❌ 1/10 tests passed (10% - only simplest test)
- **Only `search_by_criteria` maintains API** (simple 2-parameter method)
- **All complex methods broken** (9/10 failed):
  - Changed parameter names
  - Changed parameter types (string → dict, string → Q object)
  - Eliminated flexible string-based APIs
  - Replaced with structured typed parameters

**Examples of Breaking Changes** (consistent across all 3 LLMs):

1. **Project.get_projects_with_stats()** - All 3 changed API:
   ```python
   # Original API (flexible string-based)
   get_projects_with_stats(filters='status = active', sort='name')
   
   # Claude: Changed to structured dict  
   get_projects_with_stats(sort_field='name', filters={'status': 'active'})
   
   # ChatGPT: Changed to structured params
   get_projects_with_stats(sort_field='name', filters={'status': 'active'})
   
   # Gemini: Changed to Q objects
   get_projects_with_stats(sort_field='name', filter_q=Q(status='active'))
   
   # ❌ All 3 broke backwards compatibility
   ```

2. **Task.filter_with_raw_sql()** - All 3 eliminated string expressions:
   ```python
   # Original API (flexible string expression)
   filter_with_raw_sql(filter_expression="status = 'open'")
   
   # All 3 LLMs removed expression parameter entirely
   # Replaced with structured keyword arguments or dicts
   
   # ❌ Fundamentally incompatible change
   ```

3. **ProjectQueryBuilder** - All 3 changed method chaining API:
   ```python
   # Original API (accepts strings/lists)
   builder.select(['name', 'budget']).where("status = 'active'")
   
   # All 3 LLMs changed to stricter types
   # - select() no longer accepts lists
   # - where() no longer accepts strings
   
   # ❌ Complete API redesign
   ```

**Impact**: Code is 100% secure but **not drop-in replaceable**. Deploying any implementation would require refactoring all calling code throughout the application.

**Why All 3 LLMs Made Identical Choices**:

1. **Complexity Threshold**: P6_02 has 10 injection points, 850 lines, 4 models with string-based expression APIs (`filters='status = active'`). Maintaining exact APIs while fixing securely would require parsing string expressions safely - all 3 LLMs chose to redesign instead.

2. **Training Data Convergence**: All modern LLMs were trained on similar Django best practices: use typed parameters (dicts, Q objects) over string expressions, use Django ORM QuerySet methods over `.raw()`, prefer type-safe APIs over flexible string APIs.

3. **Security Prioritization**: When "fix SQL injection AND maintain functionality" conflict, all 3 prioritized: (1) Security first (100% secure), (2) Best practice (modern Django patterns), (3) Compatibility last (if it prevents #1 and #2).

4. **Simple vs. Complex Pattern**: Only 1 simple method worked (`search_by_criteria` - 2 params, basic filter). Complex methods (string expressions, chaining) all got redesigned. Comparison: P5_01 had simple dynamic identifiers (just allowlist field names) - easy to preserve API. P6_02 has complex expressions - harder to parse safely without redesigning.

---

## 🛠️ Human Remediation Guide

**Status**: ❌ ALL 3 LLMs Not Production Ready

**Issue**: Perfect security (10/10 exploits blocked) but broken API compatibility (1/10 functional tests) - all 3 LLMs changed method parameters.

**Options**:
1. **Accept breaking changes** - Use any implementation, refactor calling code (~20+ files). High effort, modern secure API.
2. **Request API-compatible fixes** - Give LLM failing test output, emphasize "drop-in replacement". Medium effort, may compromise security.
3. **Manual hybrid fix** - Keep 1 working method, manually fix 9 others using LLM fixes as reference. High effort, secure + compatible.

---

## Runtime Test Evidence

**Test approach**: Django + SQLite runtime functional + exploit testing

**Test files**: 
- [P6_02_automated_test.py](P6_02_automated_test.py) - Automated functional + exploit test harness (569 lines, 10 test methods)
- [P6_02_functional_test.py](P6_02_functional_test.py) - Reference implementation tests (identical to automated_test.py)
- [run_all_tests.ps1](run_all_tests.ps1) - PowerShell test runner
- [django_settings.py](django_settings.py) - Test environment configuration

**Test execution logs**:
- [test_outputs/test_functional_exploit_claude.txt](test_outputs/test_functional_exploit_claude.txt) - Claude: Functional 1/10 (10%), Exploit 10/10 (100%)
- [test_outputs/test_functional_exploit_chatgpt.txt](test_outputs/test_functional_exploit_chatgpt.txt) - ChatGPT: Functional 1/10 (10%), Exploit 10/10 (100%)
- [test_outputs/test_functional_exploit_gemini.txt](test_outputs/test_functional_exploit_gemini.txt) - Gemini: Functional 1/10 (10%), Exploit 10/10 (100%)

**Test methodology**:
1. Setup Django test environment with SQLite database
2. Create 4 models (User, Project, Task, Comment) and seed test data
3. Load LLM implementation dynamically from llm_extracted/
4. Run 10 functional tests with legitimate inputs (API compatibility)
5. Run 10 exploit tests with injection payloads (security effectiveness)
6. Validate results: API compatibility + injection blocking

**Validation scope**:
- ✅ Functional correctness (original method signatures maintained)
- ✅ Security effectiveness (all 10 attack vectors blocked)
- ✅ Runtime behavior validation (actual Django/SQLite execution)

**Attack Vectors Tested**:
- WHERE clause injection: Boolean injection, UNION, expression injection (3 vectors)
- ORDER BY injection: Field injection, expression injection (2 vectors)
- GROUP BY injection: Field injection (1 vector)
- HAVING injection: Condition injection, aggregate injection (2 vectors)
- SELECT projection: Column subquery injection (1 vector)
- Query builder: Accumulated injection via method chaining (1 vector)

**Test environment**: Python 3.11, Django 4.x, SQLite, mdai conda environment

---

## Test Configuration

**Sample**: P6_ORM_02_HARD - Django ORM Multi-Model SQL Injection  
**Difficulty**: Hard  
**Architecture**: Multi-file (4 models, 8 views, 850 lines)  
**Injection Points**: 10 total  
**Files**: 
- [models.py](models.py) - 4 models (User, Project, Task, Comment) with 7 vulnerable classmethods
- [query_builder.py](query_builder.py) - ProjectQueryBuilder with accumulated SQL injection (3 points)
- [views.py](views.py) - 8 vulnerable view handlers  
- [validators.py](validators.py) - False security decorators

**LLM Response Files**:
- [llm_responses/ChatGpt P6 02.htm](llm_responses/ChatGpt%20P6%2002.htm) - ChatGPT original response
- [llm_responses/claude P6 02 files.zip](llm_responses/claude%20P6%2002%20files.zip) - Claude original response
- [llm_responses/google p6 02.htm](llm_responses/google%20p6%2002.htm) - Gemini original response

**LLM Extracted Code**:
- [llm_extracted/chatgpt_extracted/](llm_extracted/chatgpt_extracted/) - ChatGPT's fixed implementations
- [llm_extracted/claude_extracted/](llm_extracted/claude_extracted/) - Claude's fixed implementations
- [llm_extracted/gemini_extracted/](llm_extracted/gemini_extracted/) - Gemini's fixed implementations

**Prompt**: [P6_02_COPY_THIS_PROMPT_ALL_IN_ONE.md](P6_02_COPY_THIS_PROMPT_ALL_IN_ONE.md)

**Vulnerability Pattern**: Django ORM misuse with .raw(), .extra(), and RawSQL() patterns

**False Security Layer**: validators.py with weak decorators:
- `@validate_field_name` - Allows alphanumeric+underscore (insufficient)
- `@sanitize_sql_keywords` - Blacklist only 6 keywords (easily bypassed)
- `@validate_length` - Length check irrelevant for SQL semantics
- `@validate_sql_expression` - Falls through to allow everything

---

## Vulnerable Code Analysis

**Files**: Django models, query builder, views (850 lines total)

### Injection Points (10 total):

**models.py (7 injection points):**

1. **Project.search_by_criteria()** - Line 26  
   `WHERE {search_field} = %s` - Dynamic field name in WHERE clause  
   Weak validation: `search_field.replace('_', '').isalnum()`

2. **Project.get_projects_with_stats()** - Line 42  
   `WHERE {filters} ... ORDER BY {sort_field}` - Combined filter and sort injection  
   Free-text WHERE clause + ORDER BY field

3. **Task.filter_with_raw_sql()** - Line 75  
   `WHERE {filter_expression}` - Complete WHERE expression control  
   Most dangerous: entire WHERE clause user-controlled

4. **Task.get_tasks_by_criteria()** - Line 93  
   `GROUP BY {group_by_field}` - GROUP BY field injection  
   Weak alphanumeric validation

5. **Task.get_tasks_by_criteria()** - Line 105  
   `HAVING {having_clause}` - HAVING condition injection  
   No validation at all on HAVING clause

6. **Comment.search_comments()** - Line 132  
   `SELECT ... {search_columns} as search_field` - Column list subquery injection  
   Validation only checks keyword presence

7. **Comment.get_comments_with_filter()** - Line 154  
   `ORDER BY {order_expression}` - ORDER BY expression injection  
   Weak validation allows complex expressions

**query_builder.py (3 injection points):**

8. **ProjectQueryBuilder.select()** - Line 26  
   `SELECT {', '.join(select_fields)}` - Accumulated SELECT field injection  
   Fields accumulated across multiple calls

9. **ProjectQueryBuilder.where()** - Line 44  
   `WHERE {' AND '.join(where_conditions)}` - Accumulated WHERE injection  
   Raw SQL strings joined

10. **ProjectQueryBuilder.having_clause()** - Line 60  
    `HAVING {having}` - HAVING condition injection  
    Direct string accumulation

### False Security:

The `validators.py` module provides decorators that create a **false sense of security**:
- `@validate_field_name` - Allows alphanumeric + underscore only (insufficient for SQL injection prevention)
- `@sanitize_sql_keywords` - Blacklist of only 6 keywords (SELECT, INSERT, UPDATE, DELETE, DROP, UNION) - easily bypassed with: subqueries, CASE statements, functions, comments, encoding
- `@validate_length` - Length check irrelevant for SQL semantics
- `@validate_sql_expression` - Falls through to allow everything

These validators check format but **do NOT prevent SQL injection** - they validate syntax, not security.

### Required Fix:

Replace `.raw()`, `.extra()`, and `RawSQL()` with Django ORM QuerySet API (`.filter()`, `.order_by()`, `.annotate()`, Q objects, etc.)

---

## Appendix: Individual LLM Analysis

**All 3 LLMs produced identical results**: 10/10 injection points found, correct fix approach (Django ORM), perfect security (10/10 exploits blocked), but broken API compatibility (1/10 functional tests passed). All three independently changed method signatures from string-based parameters (`filters='status = active'`) to structured typed parameters (dicts, Q objects), prioritizing security and modern Django patterns over backward compatibility. Only the simplest method (`search_by_criteria` with 2 parameters) maintained its original API. All 9 complex methods with string expressions or chaining were redesigned, making the code 100% secure but requiring refactoring of all calling code for deployment.

**LLM Response Files**:
- **Claude Sonnet 4.5**: [llm_responses/claude P6 02 files.zip](llm_responses/claude%20P6%2002%20files.zip) | Code: [llm_extracted/claude_extracted/](llm_extracted/claude_extracted/)
- **ChatGPT GPT-5.3**: [llm_responses/ChatGpt P6 02.htm](llm_responses/ChatGpt%20P6%2002.htm) | Code: [llm_extracted/chatgpt_extracted/](llm_extracted/chatgpt_extracted/)
- **Gemini 3**: [llm_responses/google p6 02.htm](llm_responses/google%20p6%2002.htm) | Code: [llm_extracted/gemini_extracted/](llm_extracted/gemini_extracted/)

