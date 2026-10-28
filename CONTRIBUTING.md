# Contributing to RepBridge

Small, focused contributions are welcome. Open an issue before changing the
credential model, policy language, transports or Garmin integration boundary.
For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of a public issue.

## Local workflow

Requirements: Docker with Compose v2 and BuildKit. Host Go/Python/Node are not
needed. Read [agents/README.md](agents/README.md) before behavior/auth changes,
[CONTEXT.md](CONTEXT.md) for terms. Inspect the pinned Garmin library before
adding functionality it may already provide.

```sh
docker compose -f compose.dev.yaml run --build --rm dev sh -ec 'gofmt -w cmd internal'
docker compose -f compose.dev.yaml run --build --rm test
docker compose -f compose.dev.yaml run --build --rm dev go vet ./...
docker compose -f compose.dev.yaml run --rm dev go run ./cmd/upstream-audit
docker compose -f compose.dev.yaml run --rm dev go run ./cmd/repbridge catalog check
docker compose -f compose.quickstart.yaml build repbridge
```

`make ci` also runs workflow/shell lint and the image build using Docker.
`make test` runs with `-race -count=1 -coverpkg=./...`; coverage output stays in
the disposable container. Its container has `network_mode: none`; loopback
fixture servers still work, but external Garmin/OpenAI requests cannot connect.
`make fuzz` runs short JSON/policy fuzz campaigns; `make security` checks reachable
dependency vulnerabilities. Linux development
containers may create files owned by root in the checkout; use a disposable
checkout or an appropriate host UID override when editing. These development
containers mount the source, never the Garmin key/token volumes.

Ordinary tests are offline and use fixtures. Never upload a workout, rotate
real credentials, or contact an owner's account from CI. Real-account checks
are explicit operator actions. Keep credentials and personal exports out of
commits, fixtures, screenshots and logs.

## Pull requests

- Explain the problem, intended behavior, implementation and verification.
- Keep Garmin schemas, API calls and token refresh upstream-owned.
- Update the explicit client-method coverage map and generated inventory when
  changing the pinned Garmin surface. Never discover/export future methods automatically.
- Classify new MCP capabilities, review deny lists, use the shared policy seam
  and project every result channel. New capabilities start denied.
- Preserve request contexts, account locks and single-attempt write semantics.
- Add or update offline regression coverage for behavior/security changes.
- Describe user-visible changes and migration requirements in the PR.
- Use Conventional Commits, e.g. `fix(auth): preserve rotated credentials` or
  `feat(mcp): add a classified workout capability`. Mark breaking changes with
  `!` and a `BREAKING CHANGE:` footer.

The squash-merge title controls the next version. Every merge to protected main
publishes a release after its checks pass. Follow the [release process](README.md#releases);
policy changes still require explicit owner intent.

## License and conduct

By contributing, you represent that you can submit the work under this
repository's Apache-2.0 license. Preserve third-party licenses and notices;
identify copied or generated material and review its provenance. No CLA is
required. Be respectful, provide reproducible reports and discuss technical
choices without personal attacks. Maintainers may close abusive discussions.

See the [code of conduct](CODE_OF_CONDUCT.md) for community expectations.
