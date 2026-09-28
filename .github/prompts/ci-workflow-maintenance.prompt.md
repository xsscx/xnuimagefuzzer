---
name: CI Workflow Maintenance
description: Maintain deterministic verified QA workflows
---

# CI requirements

Pin third-party actions by full commit SHA and use least privilege. CI must run
container unit tests, shell syntax checks, a sanitizer-enabled native build, QA
corpus generation, and independent validation.

Generate the same seeded corpus twice and compare normalized manifests and file
hashes. Upload only validated corpora. Do not use fallbacks that silently create
a different corpus, continue after generator failure, auto-commit generated
images, or publish legacy output as release QA data.

Keep release naming aligned with verified-image-icc-qa.tar.gz and include the
manifest and evidence directory.
