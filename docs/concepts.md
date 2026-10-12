# Concepts

## Candidate and finding

A candidate is a file the model named. It is not a finding. The customer report contains only candidates a consultant confirmed on the current snapshot. The assessment says so: model output by itself is not a finding.

Verdicts are `confirmed`, `not_actionable`, and `needs_more_info`. Only `confirmed` is written into Findings.

## Advisory-guided and exploratory

An advisory-guided check gives the model advisory text or a cached advisory id plus one CWE. An exploratory check gives the CWE and no advisory.

The report lists the two modes separately and does not add them into one figure. Exploratory checks identify the affected file far less often than advisory checks and often return files that are not affected.

In our testing on 34 published vulnerabilities, advisory-guided investigation identified the affected file in roughly 7 of 10 runs, compared with about 1 in 4 without an advisory. Results on this codebase may differ.

## CWE abstraction

The bundled catalog labels each CWE as Pillar, Class, Base, Variant, or Compound. Pillar and Class entries are broad. The review page says broad weakness classes give the model less to search for. Base and Variant children of a Class or Pillar are offered as narrower searches.

## Snapshot binding and stale verdicts

Intake freezes a snapshot and stores its SHA-256. Verdicts record that snapshot. After you replace the code, a verdict from the previous snapshot is stale. Stale verdicts stay out of the customer report until you re-confirm them on the current snapshot. Re-running a check records another run and does not increase CWE coverage.

## Coverage

Coverage counts investigations and runs per CWE, split into advisory-guided and exploratory. It is a record of what was asked, not a proof that the snapshot is free of a weakness. An empty findings list is not evidence that the snapshot has no weakness.
