# FedFence FSE 2027 - final local audit report

## Verdict

| Field | Value |
|---|---|
| Local audit | **PASSED** |
| Submission package | **COMPLETE FOR AUTHOR REVIEW** |
| External validation | **NOT COMPLETE / NOT CLAIMED** |
| Manuscript | `paper/FedFence_FSE_final_submission_candidate.pdf` |
| Pages | 12 |
| PDF SHA-256 | `048428903698c03d17804a660a8164cbf3302fb2d51d26f656afdf89a3198b84` |
| Reproduction mode | `single-driver-run` |
| Reproduction wall time | 34.89 s across 12 passed steps |

The package is internally consistent and reproducible for the stated fragment.
It does not establish representative prevalence, independently adjudicated field
accuracy, owner-confirmed findings, a live FedFence organizational deployment,
comparative-tool superiority, measured developer usability, or a machine-checked
refinement from the calculus to Python.

## Executable evidence

| Check | Result |
|---|---:|
| Unit/integration tests | 79 passed; 0 failures/errors/skips |
| Finite semantic models | 65,536 passed |
| Historical predecessor cases | 37/37 agreement |
| Predecessor self checks | 3,945 passed |
| Executable walkthroughs | 8/8 expected |
| Normalized public changes | 9; 18/18 phases source-aligned |
| Runtime-maintenance commits | 12 repositories; 11 source-stated breakage/denial reports |
| Public post-fix Actions-success records | 2 archived run IDs |
| Source-normalization frontier | 24 repositories; 7 literal/constant-foldable, 17 require evaluation |
| Vendor common-corpus product runs | 0, explicitly recorded |
| Owner-confirmed findings | 0, explicitly recorded |
| Human-study participants | 0, explicitly recorded |

## Package sanity

| Check | Result |
|---|---:|
| JSON files parsed | 40 |
| Final-layer Python compile | pass |
| Composite-action / workflow YAML parse | pass |

## Manuscript and PDF checks

| Check | Result |
|---|---|
| ACM review template | `acmsmall,screen,review,anonymous` |
| Placeholder submission ID | removed; actual venue ID can be inserted at submission time |
| References | 32/32 entries cited; no undefined or unused keys |
| Overfull boxes | 0 |
| Type 3 fonts | 0 |
| PDF Author metadata | empty |
| Mojibake probes | all zero |
| Automated preflight | openable, unencrypted, non-scanned, no XFA |
| Visual inspection | 12 pages in PDFium and pdftoppm renders; no recorded issues |

Visual inspection covered the workflow diagram, executable-output box, all four
tables, equations, and the two reference pages. No clipped text, overlap, table or
figure overflow, broken glyph, black box, missing page, or reference clipping was
observed.

## Key integrity records

| Object | SHA-256 |
|---|---|
| Manuscript source | `06f4d964dce72e859c9b386cfcdaf2c354b547e354db7fdd1d6609555cd57f82` |
| Final PDF | `048428903698c03d17804a660a8164cbf3302fb2d51d26f656afdf89a3198b84` |
| Review packet schema | `91c2c89dfa36488a0cc6aa395ad683743166f72b8a1889ee7d78835ae8757390` |
| Composite action | `ab4392ddd09abbb34d8d3fcc12a591348c94d3dcfafa99d43c94c6510135cef3` |
| Public-change corpus | `62ca73f38894bfd3e9d0d2733b3293d1a3f47793cbaa01308dcde02ad604b15c` |
| Runtime-maintenance corpus | `1717aea5fb3f6a1a5251be9104bc5bb283737bd20c6d8d333c053323f8722dd2` |
| Source-frontier sample | `16d88db8118ba67177b558616da9dfaae7534ee26bfec11b60f6ad98aebdc94e` |
| Reproduction manifest | `4cfdeb638716788703d382918aa46816b02a5066881613370049d981a53c38ee` |
| Audit JSON | `5ef7bbdd57f7404fde9fd769ffaf5a88f647b27264c7684c25d25c63a54b9090` |

## Reproduction

The complete reproduction driver ran all 12 steps in one process and recorded
`single-driver-run`. Each step has its command, elapsed time, exit code, status,
and log in the machine-readable manifest. The ordinary run validates the frozen
seven-repetition latency result; a fresh timing run is available separately.

```bash
make reproduce
make paper
make audit

# Optional fresh timing measurement
python3 scripts/benchmark_public_changes.py
```

## Claim boundary

The final evidence supports a three-valued, two-sided change review for the stated
GitHub/AWS trust fragment and source-traceable explanations of the frozen cases.
It does **not** turn purposive public commits into ground truth, successful public
workflow metadata into causal proof, required-token examples into a complete
availability language, or generated checks into deployment prevalence.
