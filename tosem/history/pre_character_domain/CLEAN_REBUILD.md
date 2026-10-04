# Clean-directory rebuild — second TOSEM revision

A separate directory was created by `scripts/check_clean_rebuild.py`. The destination had to be absent and outside the source package. **286 generated/transient files** were removed before invoking the copy's current `make reproduce`. Supplied static inputs and source code were retained.

The command exited 0. All **nine evidence steps**, table/plot generation, a fresh paper build, and **47/47 build-time consistency checks** passed. The delivered paper is the clean build's **39-page PDF**; references start on page 36. The release therefore includes the newly measured timing samples and the plot built from those samples, rather than mixing a former figure with a later CSV.

All **18 selected semantic fingerprints** agree with the preceding run, including the implementation identity. Named elapsed/total-duration fields were excluded from selected JSON comparisons, and the timing CSV comparison omits only its seconds column. Other selected verdict, witness, packet, source-record, and finite-result fields were retained. This is an independent-directory check in the same local environment, not an independent-laboratory or cross-platform replication.

Timing equality, extracted-paper-text equality, and PDF-byte equality are **not** claimed. Local measurements change across executions, and those measured values appear in the paper. Each build separately audits its raw measurements, summaries, plot values and resulting PDF hash.

- Machine record: `tosem/results/clean_rebuild_validation.json`.
- Full successful log: `logs/clean-rebuild.log`.
- Final TeX/BibTeX logs: `logs/final-paper-tex.log`, `logs/final-paper-bibtex.log`.
- Actual template identity and PDF hash: `../paper/generated/build_environment.json`.

No network or cloud account is used by reproduction. The separate optional template installer failed before downloading complete current sources and is not part of this successful offline rebuild. The archive removes TeX intermediates; a direct `make audit` without rebuilding skips the optional `main.log` check, while `make reproduce` regenerates and checks it.
