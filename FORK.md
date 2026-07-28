# Teleport SAML OSS Fork

This is a fork of [gravitational/teleport](https://github.com/gravitational/teleport) that enables SAML authentication, device trust, access requests, and login rules in the open-source edition.

## What's changed

This fork applies custom commits on top of upstream releases:

- **SAML support** — Enables SAML auth connectors in OSS (`lib/auth`, `lib/web`)
- **SAML web UI** — Adds the SAML connector editor to the web interface
- **Device trust** — Enables device trust registration, trusted devices UI, and fixes device authentication certificates
- **Access requests** — Full access request lifecycle: create, review, approve/deny, assume roles via web UI and CLI
- **Access request notifications** — Bell icon notifications for pending/approved/denied requests
- **Auto-approval** — System auto-approver bot and access monitoring rule watcher for automatic reviews
- **Login rules** — Transform or filter SSO user traits at login time via `login_rule` resources (`lib/auth/loginrule`, `lib/services/local`)
- **Slack plugin** — Standalone `teleport-slack` binary for Slack access request notifications (built in CI)
- **CI/CD pipeline** — GitHub Actions workflow to build Docker images and binary releases
- **Dockerfile** — Multi-stage build (Node.js/Rust for web UI + Go for binaries)
- **Install script** — Curl-friendly installer with checksums and systemd service
- **Test config** — Sample SAML configuration for development

## Repository layout

| File | Purpose |
|------|---------|
| `update-saml-fork.sh` | Rebases custom patches onto new upstream releases |
| `.github/workflows/build-saml-oss.yaml` | CI workflow: build, push Docker image, publish release |
| `.github/workflows/fork-tests.yaml` | CI workflow: regression gate for this fork's patches |
| `Dockerfile.saml-oss` | Multi-stage Docker build for the fork |
| `install-teleport-saml.sh` | End-user install/upgrade script |

## Continuous integration

The fork runs two workflows. Upstream's own test workflows were removed: their
`changes` gating job runs `dorny/paths-filter` without a checkout on `push`
events (upstream only fires them on `pull_request` and `merge_group`), so they
failed instantly, and their real jobs request `ubuntu-22.04-16core` /
`-32core` runners that do not exist outside the Gravitational org.

`fork-tests.yaml` deliberately does **not** reproduce upstream's suite —
`make test-go-unit` covers ~2000 packages with `-race` and targets 32-core
runners. It covers the code this fork actually changes, which is what breaks on
rebases. Everything runs on `ubuntu-latest`; do not add jobs needing the
org-only runner labels, or they will queue forever instead of failing.

| Job | Covers |
|-----|--------|
| `pins` | `Dockerfile.saml-oss` WASM/Node pins match `Cargo.lock`, `build.assets`, and `package.json` |
| `go-build` | fork binaries compile; `gofmt` on patched trees |
| `go-test` | the Go packages this fork patches |
| `web` | `pnpm type-check`, `pnpm lint`, `pnpm test` |

Some upstream tests assert OSS restrictions this fork intentionally removes
(SAML/DeviceTrust/AccessRequests entitlements, the `@teleport-access-approval-bot`
preset user). Those assertions were updated in place and are marked
`// SAML-OSS fork:` — grep for that marker after a rebase. They double as
regression tests: if the entitlements patch is ever dropped, they go red.

## Pre-rebase checklist

Do these by hand before rebasing; CI cannot check them.

1. **Confirm the target tag is a real release.** Not every upstream `vX.Y.Z` tag
   is rebaseable. A genuine release has a dedicated `branch/vX.Y.Z` branch, has
   `api/version.go` and `Makefile VERSION` bumped to match the tag, and has a
   real changelog entry. A private-security-release marker has none of these —
   `v18.10.1` was tagged on the `branch/v18` development line with its version
   constants still reading `18.10.0` and a changelog saying "This is a private
   security release". Basing on one ships unreleased dev code and mislabels the
   published release, since `build-saml-oss.yaml` derives the tag from
   `api/version.go`.

   ```bash
   git ls-remote --heads origin 'refs/heads/branch/v18*'   # is there a branch/vX.Y.Z?
   git show vX.Y.Z:api/version.go | grep Version           # does it match the tag?
   ```

2. **Re-check the WASM pins** in `Dockerfile.saml-oss`. It calls `wasm-bindgen`
   directly rather than `make ensure-wasm-deps`, so it does not self-correct.
   The `pins` CI job enforces this, but checking early avoids a wasted build.

3. **Re-check what `make ensure-webassets` stages** into
   `web/packages/teleport/public/`. `Dockerfile.saml-oss` runs `vite build`
   directly, so anything that target copies in just before the build has to be
   duplicated in the Dockerfile. Today that is the edition logo
   (`logo-{light,dark}.svg`, added upstream in v18.10.0); if upstream adds more
   staged assets, they silently 404 in the deployed UI instead of failing the
   build.

## Git remotes

| Remote | Repository |
|--------|------------|
| `origin` | `git@github.com:gravitational/teleport.git` (upstream) |
| `myfork` | `git@github.com:ivan-bax/teleport.git` (fork) |

## Release process

### 1. Update to a new upstream version

When upstream publishes a new release (e.g. `v18.8.0`):

```bash
./update-saml-fork.sh v18.8.0
# or auto-detect the latest:
./update-saml-fork.sh
```

The script will:
1. Fetch tags from `origin` (gravitational/teleport)
2. Create a temporary branch from the target tag
3. Cherry-pick all 16 custom commits in order
4. Rename the old `feature/saml-oss` and replace it with the new branch
5. Force-push to `myfork`

If a cherry-pick conflicts, the script stops and prints instructions to resolve manually.

### 2. CI builds and publishes automatically

The push to `feature/saml-oss` triggers the GitHub Actions workflow, which:

1. Reads the version from `api/version.go`
2. Builds the Docker image via `Dockerfile.saml-oss` (web UI with Node.js/Rust/WASM, then Go binaries, then slim Debian runtime)
3. Pushes to `ghcr.io/ivan-bax/teleport-saml-oss:<version>` and `:latest`
4. Extracts binaries (teleport, tctl, tsh, tbot) from the image
5. Creates a tarball + checksums
6. Publishes a GitHub Release at tag `saml-oss-v<version>`

### 3. End users install or upgrade

```bash
curl -sL https://raw.githubusercontent.com/ivan-bax/teleport/feature/saml-oss/install-teleport-saml.sh | sudo bash
```

Or pin a specific version:

```bash
curl -sL ... | sudo bash -s -- --version v18.8.0
```

The script downloads the tarball from GitHub Releases, verifies SHA256 checksums, installs binaries to `/usr/local/bin`, and creates a systemd service.

## Maintaining custom commits

The commit SHAs are hardcoded in `update-saml-fork.sh` in the `CUSTOM_COMMITS` array. If you amend or add a custom commit:

1. Push it to `feature/saml-oss`
2. Copy the new SHA
3. Update the `CUSTOM_COMMITS` array in `update-saml-fork.sh`
4. Commit the script update (and add *that* SHA to the array too)

## Slack Access Request Plugin

The `teleport-slack` binary sends Slack messages when access requests are created, and optionally allows approval/denial from Slack.

### Build

```bash
go build -o build/teleport-slack ./integrations/access/slack/cmd/teleport-slack/
```

The CI/CD pipeline also builds this binary and includes it in GitHub Releases.

### Setup

1. **Create a Slack App** at https://api.slack.com/apps:
   - Bot Token Scopes: `chat:write`, `users:read`, `users:read.email`
   - Install to your workspace and copy the Bot User OAuth Token (`xoxb-...`)
   - Invite the bot to your notification channel

2. **Create the plugin role and user** on your Teleport server:

   ```bash
   tctl create -f /dev/stdin <<'EOF'
   kind: role
   version: v7
   metadata:
     name: access-plugin
   spec:
     allow:
       rules:
         - resources: ['access_request']
           verbs: ['list', 'read', 'update']
         - resources: ['access_monitoring_rule']
           verbs: ['list', 'read']
       review_requests:
         roles: ['*']
   EOF

   tctl users add slack-plugin --roles=access-plugin
   tctl auth sign --format=file --user=slack-plugin --out=/etc/teleport/slack-identity --ttl=8760h
   ```

3. **Create the config file** at `/etc/teleport/slack-plugin.toml`:

   ```toml
   [teleport]
   addr = "localhost:3025"
   identity = "/etc/teleport/slack-identity"

   [slack]
   token = "xoxb-YOUR-TOKEN-HERE"

   [role_to_recipients]
   "*" = ["#access-requests"]

   [log]
   output = "stderr"
   severity = "INFO"
   ```

4. **Run the plugin**:

   ```bash
   teleport-slack start --config=/etc/teleport/slack-plugin.toml
   ```

   Or create a systemd service:

   ```ini
   [Unit]
   Description=Teleport Slack Plugin
   After=teleport.service

   [Service]
   Type=simple
   ExecStart=/usr/local/bin/teleport-slack start --config=/etc/teleport/slack-plugin.toml
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

## Auto-Approval Rules

Access requests can be auto-approved using access monitoring rules:

```bash
tctl create -f /dev/stdin <<'EOF'
kind: access_monitoring_rule
version: v1
metadata:
  name: auto-approve-editor
spec:
  subjects:
    - access_request
  condition: 'access_request.spec.roles.contains("editor")'
  desired_state: reviewed
  automatic_review:
    integration: builtin
    decision: APPROVED
EOF
```

The `@teleport-access-approval-bot` user (created automatically) submits the review. Change `decision` to `DENIED` to auto-deny.

## Login Rules

Login rules transform or filter the traits a user receives from an SSO identity
provider (SAML/GitHub/OIDC) at login time. Upstream this is Enterprise-only; this
fork implements the auth-server side (storage, the gRPC CRUD service, and the
evaluator) so `login_rule` resources work in OSS.

Manage rules with `tctl`:

```bash
tctl create -f login-rule.yaml   # create (errors if it exists)
tctl get login_rules             # list all rules
tctl rm login_rule/<name>        # delete
```

A rule sets **exactly one** of `traits_map` or `traits_expression`. Rules are
applied in ascending `priority` order, and each rule's output traits feed into
the next. Incoming IdP traits are exposed to expressions as `external`.

`traits_map` fully defines the output trait set (unreferenced traits are
dropped). Use `external.<trait>` to carry values forward:

```yaml
kind: login_rule
version: v1
metadata:
  name: set-groups
spec:
  priority: 0
  traits_map:
    groups:
      - "external.groups"   # keep IdP-provided groups
      - everyone            # add a literal value
    logins:
      - "external.username"
```

`traits_expression` mutates the `external` dict in place (helpers include
`add_values`, `put`, `remove`):

```yaml
kind: login_rule
version: v1
metadata:
  name: add-default-group
spec:
  priority: 1
  traits_expression: external.add_values("groups", "everyone")
```

Test rules against sample traits without saving them (optionally combining with
rules already stored in the cluster):

```bash
# Traits are read from a positional JSON file or stdin.
echo '{"groups": ["devs"], "username": ["alice"]}' | \
  tctl login_rule test --resource-file login-rule.yaml --load-from-cluster
```

The names of applied rules are recorded on the SSO diagnostic info and in the
`login_rule.create`/`login_rule.delete` audit events. Editing rules requires the
`login_rule` resource verbs, which the preset `editor` role already grants.

## Docker

Pull the latest image:

```bash
docker pull ghcr.io/ivan-bax/teleport-saml-oss:latest
```

Or a specific version:

```bash
docker pull ghcr.io/ivan-bax/teleport-saml-oss:18.7.2
```

Exposed ports: 3023, 3024, 3025, 3080, 443.
