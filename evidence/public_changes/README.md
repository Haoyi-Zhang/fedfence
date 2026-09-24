# Captured public OIDC trust-change hunks

These files preserve the relevant trust-policy evidence for the nine public
changes in `study/public_change_corpus.json`.  Each row records repository, full
commit SHA, affected file(s), commit message, source-stated review goal, and the
removed/added values used by manual normalization.

The study verifies each local snapshot by SHA-256 and checks that every declared
removed/added literal occurs in the captured source.  The frozen screening
manifest records 17 candidates, nine inclusions, and eight exclusions.

The files are relevant hunks, not complete repository snapshots.  They are not
independently adjudicated intent labels, owner-confirmed vulnerabilities, or
proof that a reported deployment behavior occurred.  The canonical public commit
URL remains in the corpus record.
