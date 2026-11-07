# Product

<!-- impeccable:product-schema 1 -->

> Written from `docs/PROD_ARCHITECTURE.md` and the code. The interview was skipped at the
> user's request; every fact below comes from those sources, not from a confirmed interview.

## Platform

web

## Users

The people who run Telltale for its consumers: a small admin / analyst team (Cloudflare Access
allows up to 50) using the SOC console at a desk to watch the device fleet, investigate odd traffic
and act on it. Roles: viewer, analyst, admin.

## Product Purpose

Telltale is behavioral ransomware detection for Windows. An agent on each PC scores new processes;
ambiguous ones go to a cloud Tier-2 model. The SOC console shows every registered device, its IPs,
every Tier-2 request, rejected requests, reports users send from the agent's dialog, licences and
the admin audit trail, and lets admins revoke devices and block IPs.

## Positioning

Only verified installs (TPM-bound device keys, signed requests) can use Tier 2, and the console is
where that trust is managed: who is verified, who is lower trust, who is abusing the API.

## Operating Context

Desktop browser behind Cloudflare Access plus a Cognito passkey / TOTP login. Long sessions with
the live log open; quick checks of the overview; occasional destructive actions (revoke, block)
that need a fresh sign-in.

## Capabilities and Constraints

- Views: Overview, Devices, Device detail (IP history), IPs, Live log, Rejected, Reports, Licences,
  Audit, Cloud → AWS and Cloud → Cloudflare. Licences are read-only.
- Plain HTML / CSS / JS, no build step, served by Cloudflare Pages; API at `/admin/*`.
- Strict CSP: scripts and styles from the same origin only; no third-party fonts or CDNs.
- Device-supplied strings (names, paths, IPs) are untrusted and are shown as text only.
- The Cloud pages (step 6) chart requests per minute with spikes marked, and show free-quota bars.

## Evidence on Hand

No real fleet data yet; the console has only run against sample data.

## Product Principles

1. Trust state is the first thing an operator reads: verified, lower trust, failed, revoked.
2. Fast to scan, slow to destroy: reading is instant, revoke / block always confirms.
3. Untrusted data never becomes markup.

## Accessibility & Inclusion

Keyboard operable, visible focus, status never by color alone, 4.5:1 text contrast, reduced motion.
