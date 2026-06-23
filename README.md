# Teleport — SAML OSS Fork

> **This is an unofficial community fork of [gravitational/teleport](https://github.com/gravitational/teleport).**
> It is **not** affiliated with, endorsed by, or supported by Gravitational, Inc.
> For the official product, documentation, and commercial support, visit
> [goteleport.com](https://goteleport.com).

This fork tracks upstream Teleport releases on the `feature/saml-oss` branch and
unlocks several capabilities that upstream ships only in Teleport Enterprise —
making them available in a source-built, **fully open-source (AGPL-3.0)** binary.

It does this either by removing build/entitlement gating around code that already
exists in the open-source tree, or by reimplementing the server side from scratch
where the original lived only in the closed-source `e/` submodule. No proprietary
Enterprise code is included or redistributed — the `e/` submodule is empty in this
fork.

## What this fork enables

| Feature | What you get |
|---------|--------------|
| **SAML SSO** | SAML auth connectors plus the connector editor in the web UI |
| **Device Trust** | Device enrollment, trusted-device UI, and device-bound certificates |
| **Access Requests** | Full request lifecycle (create, review, approve/deny, role assumption) via web UI and CLI, with in-app notifications |
| **Auto-approval** | Auto-approver bot driven by access monitoring rules |
| **Login Rules** | Transform or filter SSO traits at login time via `login_rule` resources |
| **Slack plugin** | Standalone `teleport-slack` binary for access-request notifications |

Everything else behaves exactly like upstream Teleport. For build, release, install,
and configuration details specific to this fork, see **[FORK.md](./FORK.md)**.

## Quick start

Install or upgrade with the fork's installer:

```bash
curl -sL https://raw.githubusercontent.com/ivan-bax/teleport/feature/saml-oss/install-teleport-saml.sh | sudo bash
```

Or run via Docker:

```bash
docker pull ghcr.io/ivan-bax/teleport-saml-oss:latest
```

Building from source, the release process, and the Slack/auto-approval/login-rule
setup are all documented in **[FORK.md](./FORK.md)**.

## About Teleport

Teleport provides connectivity, authentication, access controls, and audit for
infrastructure. It is a single Go binary that acts as an identity-aware access
proxy and certificate authority, issuing short-lived certificates for SSH,
Kubernetes, databases, RDP, and internal web apps.

For the full product overview, architecture, and admin/user guides, refer to the
upstream project and its documentation:

* Upstream repository: https://github.com/gravitational/teleport
* Documentation: https://goteleport.com/docs/
* Architecture: https://goteleport.com/docs/reference/architecture/
* Getting started: https://goteleport.com/docs/get-started/

## License

This fork honors and preserves Teleport's upstream licensing in full. No license
terms have been changed, removed, or relaxed.

* The Teleport API module (all code under [`/api`](./api)) is available under the
  [Apache 2.0 license](./api/LICENSE).
* The remainder of the source in this repository is available under the
  [GNU Affero General Public License v3.0](./LICENSE). If you build, run, or
  distribute this code — including over a network — you must comply with the AGPL,
  which is why the complete source for this fork, including all modifications, is
  published in this repository.

> The features unlocked here are licensed under the same AGPL-3.0 as the rest of
> the open-source tree. The "modified Apache 2.0" Community Edition license that
> Gravitational applies to its own pre-built binaries
> ([`build.assets/LICENSE-community`](./build.assets/LICENSE-community)) does **not**
> apply to binaries you build from this source.

"Teleport" and "Gravitational" are trademarks of Gravitational, Inc. They are used
here only to identify the upstream project this is derived from; their use does not
imply any affiliation or endorsement.
