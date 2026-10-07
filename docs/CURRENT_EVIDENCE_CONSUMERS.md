# Current evidence consumers

Run from the artifact directory, with Python 3.10+ and its standard library:

```sh
python -B coherence_tests/test_evidence_consumers.py -v
python -B scripts/audit_current_science.py --receipt tosem/results/native-science/_fresh-science/current-science-receipt.json --evidence-root tosem/results/native-science
python -B scripts/generate_tosem_tables.py --current-receipt tosem/results/native-science/_fresh-science/current-science-receipt.json --evidence-root tosem/results/native-science --check
# Write tables only after complete validation (or use make tables):
python -B scripts/generate_tosem_tables.py --current-receipt tosem/results/native-science/_fresh-science/current-science-receipt.json --evidence-root tosem/results/native-science
```

The generic storage folder contains the original 225 output files and eight
original sidecars of main-push run 37670050420, attempt 1, commit
07258c854b9136504952d2b842866074500847bf. Receipt bytes and its internal relative
names are unchanged. Storage lies inside the assembler's already-declared
`tosem/results` generated exclusion; the audited source root remains this
artifact, not a frozen copied source tree. The preparation digest, output-origin
map, 56 scientific files, 12 study inputs and each output digest must agree.
The preparation's full support snapshot is historical: edited consumer wrappers
are not claimed as files executed by that earlier campaign.

Current unit/finite/matcher/study tables use the explicitly selected native
receipt. Identity is derived from its actual driver and adjacent recorded CI
identity, with receipt/preparation/identity byte digests in generated provenance.
These recorded fields are not provider authentication. No run ID is invented
when a valid local fresh receipt has no CI sidecar. The retained sidecar audit
must agree with the passive recheck; twelve new consumer methods are separate
from 204 ordinary tests, seven scalar methods, eight assembler methods and nine
scientific stages. CI runs consumer tests separately and retains their log.

The scaling table and plot continue to use the distinct supplied historical
`tosem/results/local_scaling.csv`: 54 rows, 18 summary cells, three repetitions
per cell and 18 recorded warm-ups. CSV digest, classifications, repetition
indices, finite positive values, medians and observed extrema are checked before
**any** output directory or table is written. All selected tables are rendered
in memory first. This prevents malformed late inputs from partially replacing
valid existing tables; it is not an atomic filesystem transaction for disk
failures during the subsequent write phase. No comparative timing claim follows.

`make native-audit` and `make tables` are the passive current commands.
`CURRENT_RECEIPT` and `CURRENT_EVIDENCE_ROOT` can explicitly select another valid
campaign. The direct no-receipt generator still refuses the historical 194-test
record against current 204-test discovery. It is retained for the unchanged
ten-stage driver, which first creates its own genuinely fresh outer records.
`make evidence`, `make reproduce` and `make audit` remain the separate original
ten-stage route, including eight seeded faults and the PDF audit. They overwrite
generated outputs, so execute in a fresh disjoint full-project scratch copy,
not this retained evidence delivery. Nine-stage acceptance does not make those
ten-stage/PDF gates green. No ten-stage rerun was performed for this consumer fix.
