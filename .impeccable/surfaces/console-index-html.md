---
version: 1
slug: "console-index-html"
primary_target: "console/index.html"
related_targets: ["console/style.css","console/app.js"]
---

# SOC console surface brief

Scope: the whole SOC console (console/index.html, style.css, app.js). Mode: Operate.
Audience: a small analyst / admin team at a desk; long sessions with the live log open, quick overview checks, rare revoke / block.
Job: read trust state first, scan devices / IPs / requests, act (revoke, restore, block, unblock) only after a confirmation.
Constraints: PRODUCT.md (strict CSP, self-hosted only, device strings as text, status never by colour alone).
Chosen direction: Triage tags (user chose it from the roll). Memorable moment: the fleet sorted into three triage bands (Revoked / Lower trust / Verified) on Overview.

## Direction contract

THESIS: Trust is triage. Every device carries a triage tag (Revoked, Lower trust, Verified) and every request one more state, Failed; the tag strip means trust and nothing else. The console refuses the black-and-neon "hacker terminal" default and the grey SaaS card grid.

OWN-WORLD: Manila card-stock ground (tinted light), ink-black nav rail, black ink type. Four triage inks used only for state: black, red, amber, green, each with its word and a band position. Hairline rules, tabular figures, the system UI sans for everything (hierarchy by size and weight, no second face); mono only for IDs, IPs, hashes and paths. Revoked rows print in greyscale.

STORY: The operator opens Overview, reads how many devices sit in each band, sees what changed in the last hour, opens a device, reads its tag and IP history, and revokes with a deliberate confirmation.

FIRST VIEWPORT: Left ink rail (brand, nav, signed-in user). Main: page title, then the triage board: three stacked bands Revoked / Lower trust / Verified (devices are never "failed"; failure is a request state), each a filled name tab, count, share-of-fleet bar and a link to the filtered device list; under it a strip of 1-hour figures (requests, rejected, failed verification, KILL, p50/p99); under that the latest requests table.

FORM: Triage tag, candidate 5 of 7 on the ordered list; seed:e8353b02f1663fea. Raises: hierarchy by scale contrast alone (from the type specimen); strict hairline module rules (from high-density web); new live-log rows stay marked until seen (from the gate board); revoked prints greyscale (from the goods catalog); flat colour, no gradients or glow (from the guide map).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
