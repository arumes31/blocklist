# Blocklist

<!-- impeccable:product-schema 1 -->

## Platform

web

## Product Purpose

Blocklist manages blocked IPs, whitelist entries, protected exclusions, integrations, API access, and administrator permissions. Redis, PostgreSQL, and the Go server supply the existing behavior.

## Users

Repository evidence: viewers inspect activity; operators manage IP enforcement; administrators configure access and integrations. The exact deployment audience is not specified.

## Capabilities and Constraints

The initial October 2026 redesign was visual only. The user subsequently approved retaining it in the local development app and adding managed roles, configuration-ready Microsoft Entra sign-in, separate system/event logs, and an additive local database migration. Preserve existing accounts and workflows, including local TOTP recovery access, filters, live updates, maps, exports, and scoped tokens. Support desktop, tablet, and mobile layouts.

## Brand Commitments

The user requests a sleek, contemporary, generalized appearance with refined neutral surfaces, crisp typography, and subtle motion. Restore the original animated logo throughout the shell. Modernize the login particle field while preserving its visual character. Product name: Blocklist.

## Evidence on Hand

Existing Go HTML templates in cmd/server/templates, embedded assets, and the local Docker development stack at http://localhost:5050. No production data or claims are needed for this visual redesign.

## Product Principles

- Operational clarity and readable data come first.
- Preserve functionality throughout visual changes.
- Use consistent navigation and controls across all pages.
- Make the same tasks accessible at narrower viewports.
