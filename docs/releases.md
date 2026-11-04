# Releases

Every merge to protected `main` automatically publishes a release through
[GoReleaser](https://goreleaser.com/), starting at **0.1.0**. CI, fuzzing,
secret/dependency scans, and snapshot image checks must pass before publication.
Release jobs are serialized with a queue; later merges do not cancel pending
releases. GitHub's queue currently holds up to 100 pending runs.

Use a Conventional Commit title for each squash-merged PR:

| Change | Example | Version increase |
| --- | --- | --- |
| Compatible fix | `fix(auth): preserve the rotated session` | Patch |
| Compatible feature | `feat(mcp): expose a classified tool` | Minor |
| Breaking change before 1.0 | `feat!: change the policy schema` | Minor |
| Breaking change from 1.0 onward | `feat!: change the policy schema` | Major |
| Documentation, build, maintenance | `docs: clarify setup` | Patch |

Pinned [SVU](https://github.com/caarlos0/svu) calculates the next SemVer from
commit messages, with a patch increase even for maintenance-only changes.
The immutable Git tag is the version source of truth. There is no version-bump
commit or privileged bypass of main protection. Source builds report `dev`;
published binaries and MCP metadata report the release version.

GoReleaser produces Linux amd64/arm64 archives, source archives, SHA-256
checksums and multi-platform GHCR images. Published images carry SBOM and
provenance; snapshot checks work with classic Docker stores too. Releases and
image tags are immutable: a rerun skips an already published commit. A partial
publication requires reconciliation, not overwriting an existing image or tag.

To validate packaging locally without publication:

```sh
docker compose -f compose.release.yaml run --build --rm release check
docker compose -f compose.release.yaml run --build --rm snapshot release --snapshot --clean --skip=publish
```

Snapshot builds load both architecture images locally and scan them. They need
Docker socket access and perform no registry upload or GitHub release creation.
The `release check` service has neither that socket nor a token. Publishing
credentials exist only in the separate publisher service in GitHub Actions.
A manual workflow dispatch can retry a failed release after reconciliation.

Source archives come from the tagged Git tree. Keep only reviewed public files
tracked. Audit results belong in review discussions, not committed reports.
The changelog for each version is generated in
[GitHub Releases](https://github.com/krzysztof-gre/repbridge/releases).
