# E2E Test Infra: Multi-Modal Scanner

## Test Philosophy
- Opaque-box, requirement-driven. No dependency on implementation design.
- Methodology: Category-Partition + BVA + Pairwise + Workload Testing.

## Feature Inventory
| # | Feature | Source (requirement) | Tier 1 | Tier 2 | Tier 3 |
|---|---------|---------------------|:------:|:------:|:------:|
| 1 | Multi-Modal Prompting | ORIGINAL_REQUEST | 5      | 5      | ✓      |
| 2 | Parallel API Execution | ORIGINAL_REQUEST | 5      | 5      | ✓      |
| 3 | Robust Fallback | ORIGINAL_REQUEST | 5      | 5      | ✓      |
| 4 | Result Merging | ORIGINAL_REQUEST | 5      | 5      | ✓      |

## Test Architecture
- Test runner: `pytest` executed via `python -m pytest tests/test_e2e_multi_modal_scanner.py -v`. Pass semantics: exit code 0.
- Test case format: Python functions utilizing `unittest.mock` and `responses` for API simulation, validating `InstantScanResult` via schemas/assertions.
- Directory layout: tests in `tests/` directory.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | High Concurrency Scans | F1, F2 | High |
| 2 | Sustained Throughput | F2 | High |

## Coverage Thresholds
- Tier 1: ≥5 per feature
- Tier 2: ≥5 per feature (where boundaries exist)
- Tier 3: pairwise coverage of major feature interactions
- Tier 4: ≥5 realistic application scenarios
