# Review notes — changes from the submitted PDF

I reviewed the original *Final Forensic Report* before publishing it here. The technical outcome is unchanged; these are the corrections and additions.

## Corrections

| Original | Issue | Fixed in this version |
|---|---|---|
| Two figures both numbered **Figure 4** | Duplicate numbering | Renumbered 1–7 |
| Checklist: CloudTrail evidence → "Figure 3", detection email → "Figure 4", boundary → "Figure 5" | References pointed at the wrong figures | Checklist rebuilt against the new numbering |
| Checklist: Security analysis → "Section 6", Lessons learned → "Section 7" | Actual sections were 5 and 6 | Linked to the correct sections |
| Design diagram shows **Lambda → IAM** | Implementation and tests used **SSM Automation** | Diagram kept as a planning artefact; text and Mermaid diagram reflect SSM; Lambda discussed as an alternative (§8.3) |
| "SoloGaurd" | Misspelling of "Guard" | Kept, because it is the real resource name in AWS and in the screenshots; noted in the README |
| Repeated words ("and and", "the tests I completed the completed test") | Typos | Fixed |
| Checklist cites a "Victim quarantine boundary" figure | That figure was actually the alarm email; no IAM console screenshot exists | Boundary evidence mapped to the CLI error (Fig. 6), which names the boundary ARN; IAM/SSM screenshots listed as gaps below |

## Additions

- Threat model, MITRE ATT&CK mapping and objectives.
- Why `GetSecretValue` needs the **read-only management events** rule state.
- Why the active-defense rule filters for **success only** (`errorCode` absent).
- Why an **explicit** deny boundary is safer than an implicit one.
- Side-by-side comparison of kill-switch vs quarantine.
- Timeline of all timestamps visible in the evidence.
- NIST CSF 2.0 mapping (without claiming compliance).
- Reconstructed configuration (JSON/YAML), deploy / test / evidence / reset / teardown scripts.
- Production-hardening guidance, including STS session revocation.
- Redaction of account ID and key IDs in every screenshot.

## Evidence gaps worth closing in a re-run

1. Screenshot of the **Flow 2** email (EventBridge event JSON).
2. Screenshot of the **SSM Automation execution** with status `Success`.
3. Screenshot of **IAM → Users → Victim** showing the permissions boundary.
4. Screenshot of the kill-switch result (`InvalidClientTokenId`) to support the authentication-vs-authorization finding.
5. Measured detection latency for Flow 1 and Flow 2 (event time vs email time).

`scripts/collect-evidence.sh` captures items 2 and 3 as JSON.
