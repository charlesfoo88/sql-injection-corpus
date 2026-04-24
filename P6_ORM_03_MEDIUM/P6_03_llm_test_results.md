# P6_03: LLM Test Results

**Sample:** P6_03 — Django ORM misuse with .extra() method allowing SQL injection through ORDER BY, WHERE, SELECT, and table/join specifications
**Analysis Date:** 2026-04-24
**Model Used:** claude-sonnet-4-5-20250929

## Injection Points Identified

| LLM | Points Identified | Status |
|-----|-------------------|--------|
| Claude | 6/6 | ✅ |
| ChatGPT | 6/6 | ✅ |
| Gemini | 6/6 | ✅ |

## Fix Approach

| LLM | Technique Used | Assessment |
|-----|----------------|------------|
| Claude | Whitelist validation + Django ORM methods (order_by, filter, annotate, select_related) | ✅ Correct |
| ChatGPT | Whitelist validation + Django ORM methods (order_by, filter, annotate, select_related) | ✅ Correct |
| Gemini | Whitelist validation + Django ORM methods (order_by, filter, annotate, select_related) | ✅ Correct |

## Summary Observations

- Convergent failure across all three LLMs: All models correctly identified 6/6 injection points and produced technically secure fixes (11/11 exploits blocked), but only 1 of 4 legitimate queries functioned after remediation. No LLM preserved the original API behavior.

- Over-refactoring failure mode: Each LLM independently chose to refactor the .extra() API to a restrictive whitelist — accepting only predefined expression names, table references, and filter formats. Security was achieved by eliminating flexibility rather than by parameterizing inputs.

- Pattern-level finding, not model-specific: The identical failure mode across Claude, ChatGPT, and Gemini indicates the outcome is driven by the .extra() pattern itself, not LLM-specific weaknesses. This contrasts with P6_01 (.raw() pattern) where 2 of 3 LLMs succeeded.

- API-security tension specific to .extra(): Unlike .raw(), which accepts a complete query string that can be parameterized, .extra() takes SQL fragments (identifiers, expressions, clauses) that cannot be parameterized in place. Securing these inputs requires restricting what is allowed, which inherently changes the API contract.

- Medium Complex architecture, Hard-tier outcome: P6_03's architectural profile matches Medium Complex (single file, single ORM), but produced the same over-refactoring failure mode observed in P5_02 and P6_02 (Hard tier, 0/3 success). This suggests complexity tier based on code structure does not always predict fix difficulty; API design can create security-functionality tension independent of structural complexity.

- Human remediation required: No fix is deployable as-is. A production-acceptable solution would require either (a) extending the whitelist approach with documented API changes communicated to callers, or (b) accepting .extra() restrictions and migrating to QuerySet API methods where possible.

## Per-LLM Analysis

### Claude
- **Summary:** Replaces all `.extra()` calls with safe Django ORM methods and implements comprehensive whitelists for user-controlled parameters
- **Strengths:**
  - Completely removes `.extra()` method, eliminating the vulnerable API surface
  - Implements `ALLOWED_SORT_FIELDS` whitelist with support for ascending/descending order and related field access
  - Redesigns `get_filtered_articles()` to accept Django filter kwargs instead of raw SQL WHERE clauses
  - Redesigns `get_articles_with_computed_column()` with predefined computation types using Django's F() expressions and ExpressionWrapper
  - Implements `get_articles_with_extra_table()` with relation_type parameter and select_related() for safe joins
  - Includes ValidationError exceptions for invalid inputs
  - Provides multiple predefined computation types (engagement_score, view_like_ratio, popularity_index)
- **Concerns:**
  - API signature changes may require updating calling code (accepts different parameter types)
  - Less flexible than original implementation for dynamic use cases

### ChatGPT
- **Summary:** Replaces `.extra()` with Django ORM safe methods and uses whitelists to validate user input
- **Strengths:**
  - Removes all `.extra()` method usage
  - Implements whitelist validation for sort fields in `get_article_stats_by_field()`
  - Changes `get_filtered_articles()` to accept dictionary of filters instead of raw SQL
  - Uses predefined dictionary of safe expressions in `get_articles_with_computed_column()`
  - Simplifies `get_articles_with_extra_table()` to use select_related() with table name validation
  - Raises ValueError for invalid inputs
- **Concerns:**
  - `get_articles_with_computed_column()` requires expression parameter to be a key name rather than an expression, which changes the API semantics significantly
  - Limited predefined expressions (only views_plus_likes and engagement_score)
  - `get_articles_with_extra_table()` ignores the join_condition parameter entirely, reducing functionality

### Gemini
- **Summary:** Eliminates `.extra()` usage and implements whitelist-based validation with Django ORM safe alternatives
- **Strengths:**
  - Completely removes `.extra()` method calls
  - Uses class-level constants for whitelists (`_ALLOWED_SORT_FIELDS`, `_ALLOWED_COMPUTED_COLUMNS`, `_ALLOWED_RELATED_TABLES`)
  - Implements `order_by()` with whitelist validation for sort fields
  - Redesigns `get_filtered_articles()` to accept filter dictionary
  - Uses predefined F() expressions dictionary for computed columns
  - Implements `select_related()` with whitelist validation for table joins
  - Includes comprehensive documentation with examples
  - Properly handles descending sort order by stripping '-' prefix during validation
- **Concerns:**
  - API changes from original implementation (different parameter expectations)
  - `get_articles_with_extra_table()` signature changed to single parameter, removing join_condition control

## Functional Tests
| LLM | Functional Passed | Status |
|-----|-------------------|--------|
| Claude | 1/4 | ❌ |
| ChatGPT | 1/4 | ❌ |
| Gemini | 1/4 | ❌ |

## Exploit Tests
| LLM | Exploits Blocked | Status |
|-----|------------------|--------|
| Claude | 11/11 | ✅ |
| ChatGPT | 11/11 | ✅ |
| Gemini | 11/11 | ✅ |

## Production Ready
| LLM | Verdict |
|-----|---------|
| Claude | ❌ NO |
| ChatGPT | ❌ NO |
| Gemini | ❌ NO |