# Remediation handoff for Acme

Confirm the weakness in the named file before changing code. This handoff is not a patch and it has no line numbers.

Candidates below are consultant-confirmed on the current snapshot. Stale and unreviewed candidates are omitted.

## app.py

- Status: confirmed
- Mode: advisory-guided
- CWE: CWE-89
- What to look for: Look through app.py for Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'). Confirm the weakness before changing code.

MITRE mitigations:

- For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.
- When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.
- Use an application firewall that can detect attacks against this weakness. It can be beneficial in cases in which the code cannot be fixed (because it is controlled by a third party), as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth.
- When using PHP, configure the application so that it does not use register_globals. During implementation, develop the application so that it does not rely on this feature, but be wary of implementing a register_globals emulation that is subject to weaknesses such as CWE-95, CWE-621, and similar issues.
