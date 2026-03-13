# Teleport SAML OSS Fork

This is a fork of [gravitational/teleport](https://github.com/gravitational/teleport) that enables SAML authentication and device trust in the open-source edition.

## What's changed

This fork applies 16 custom commits on top of upstream releases:

- **SAML support** — Enables SAML auth connectors in OSS (`lib/auth`, `lib/web`)
- **SAML web UI** — Adds the SAML connector editor to the web interface
- **Device trust** — Enables device trust registration, trusted devices UI, and fixes device authentication certificates
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
