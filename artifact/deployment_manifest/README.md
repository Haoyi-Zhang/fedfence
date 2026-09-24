# Deployment-manifest interface

`example_manifest.json` demonstrates the operational input boundary used by FedFence. A scanner, cloud export, or reviewer can supply rows containing a trust document, an intent basis, governance premises, and optional source hashes. The submitted example references already-anonymized cases in this artifact so the paper can remain double blind and offline.

Run:

```bash
python3 scripts/run_deployment_manifest.py
```

To analyze another manifest, set `FEDFENCE_DEPLOYMENT_MANIFEST=/path/to/manifest.json`. The manifest runner does not contact cloud accounts or repositories; it turns provided role-review objects into the same verdict and replay fields used for the registered evaluation.
