# SQL Injection Corpus - Strategy Document

**Project**: MDAI Industry Project - Human & Neuro-Symbolic AI Remediation  
**Last Updated**: March 11, 2026  
**Status**: 6/8 vulnerable samples complete, 0/2 benign samples

---

## Corpus Overview

| # | Sample ID | Pattern | Difficulty | Injection Points | Status | LLM Success Rate |
|---|-----------|---------|------------|------------------|--------|------------------|
| 1 | P5_DYNAMIC_IDENTIFIERS_01_MEDIUM | Dynamic Identifiers | Medium | 6 | ✅ Complete | 2/3 (67%) |
| 2 | P5_DYNAMIC_IDENTIFIERS_02_HARD | Dynamic Identifiers | Hard | 13 | ✅ Complete | 0/3 (0%) |
| 3 | P6_ORM_01_MEDIUM | ORM Misuse | Medium | 6 | ✅ Complete | 2/3 (67%) |
| 4 | P6_ORM_02_HARD | ORM Misuse | Hard | 10 | ✅ Complete | 0/3 (0%) |
| 5 | P9_SECOND_ORDER_01_VERY_HARD | Second-Order Injection | Very Hard | 10 | ✅ Complete | 0/3 (0%) |
| 6 | P4_WHERE_MULTI_01_MEDIUM | WHERE Multiple Conditions | Medium | 10 | ✅ Complete | 3/3 (100%) |
| 7 | P4_WHERE_MULTI_02_HARD | WHERE Multiple Conditions | Hard | TBD | ⬜ Planned | Target: 3/3 (100%) |
| 8 | P8_STORED_PROC_01_HARD | Stored Procedure Dynamic SQL | Hard | TBD | ⬜ Planned | Target: 1-2/3 (33-67%) |
| 9 | BENIGN_01 | Safe Parameterization Pattern | N/A (Benign) | 0 | ⬜ Planned | N/A (Reference) |
| 10 | BENIGN_02 | Safe ORM Pattern | N/A (Benign) | 0 | ⬜ Planned | N/A (Reference) |
