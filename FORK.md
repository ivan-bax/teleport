# Teleport SAML OSS Fork

This is a fork of [gravitational/teleport](https://github.com/gravitational/teleport) that enables SAML authentication, device trust, and access requests in the open-source edition.

## What's changed

This fork applies custom commits on top of upstream releases:

- **SAML support** — Enables SAML auth connectors in OSS (`lib/auth`, `lib/web`)
- **SAML web UI** — Adds the SAML connector editor to the web interface
- **Device trust** — Enables device trust registration, trusted devices UI, and fixes device authentication certificates
- **Access requests** — Full access request lifecycle: create, review, approve/deny, assume roles via web UI and CLI
- **Access request notifications** — Bell icon notifications for pending/approved/denied requests
- **Auto-approval** — System auto-approver bot and access monitoring rule watcher for automatic reviews
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
| `Dockerfile.saml-oss` | Multi-stage Docker build for the fork |
| `install-teleport-saml.sh` | End-user install/upgrade script |

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
