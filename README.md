<p><img src="docs/assets/repbridge-reversed.png" width="640" alt="RepBridge — white bridge symbol and wordmark on charcoal"></p>

# RepBridge

**Garmin Connect tools for AI assistants, with owner-controlled permissions.**

RepBridge is a self-hosted MCP server built around
[`go-garmin`](https://github.com/ndeloof/go-garmin). Let an assistant create,
edit and schedule workouts, and queue them for your device. A local policy
controls allowed operations, returned fields and resource conditions.

**Experimental · one Garmin account per deployment · Apache-2.0**

## Quick start

You need **Docker with Compose v2 and BuildKit**, plus a browser. From a trusted
checkout or extracted source release, run:

```sh
docker compose -f compose.quickstart.yaml run --build --rm --service-ports setup
```

Open the printed URL in Chrome and sign in **on Garmin's page**, including OTP
if requested. Allow third-party cookies for sign-in. Setup generates a vault key
and stores encrypted tokens in separate Docker volumes; no host Go is required.

Connect a stdio MCP client with the following configuration, replacing both
`/path/to/repbridge` paths with your checkout's absolute path:

```json
{
  "mcpServers": {
    "repbridge": {
      "command": "docker",
      "args": [
        "compose", "--project-directory", "/path/to/repbridge",
        "-f", "/path/to/repbridge/compose.quickstart.yaml",
        "run", "--rm", "--no-deps", "-T", "mcp"
      ]
    }
  }
}
```

Require approval for writes in your MCP client. Start with `get_permissions`,
`garmin_session_status` and `list_workouts`. Then try the
[synthetic workout example](docs/workouts.md).

For **ChatGPT through an OpenAI tunnel**, authenticated HTTP, remote Docker
hosts or existing installations, follow [setup and connections](docs/connections.md).
Preserve existing key/data volumes and deployment identity when upgrading.

## Permissions

The starter policy allows selected workout reads and minimal device discovery.
Creating, editing, scheduling and sending workouts is restricted to names
beginning with `AI: `. **Activity and health reads are disabled.** Other writes,
including deletion, are explicitly denied.

Policy is enforced on the server for every invocation and response. Default deny
and explicit-deny precedence apply; the MCP client is responsible for human
approval. Only the owner can edit the mounted policy. See
[policy rules and examples](docs/access-policy.md).

## Status and limits

- Uses **unofficial Garmin endpoints**; independent of Garmin and OpenAI.
  See the [integration boundary and official alternatives](docs/garmin-integration.md).
- Covers 146 pinned library methods through 148 classified actions. These are
  offline mapping/schema checks, **not proof every endpoint was tested live**.
  See [coverage and limits](docs/capabilities.md).
- A queue receipt does not prove watch delivery. Browser/OTP, refresh, client
  compatibility and device sync need [operator validation](docs/manual-validation.md).
- Allowed responses reach your assistant/model provider. Host/Docker admins are
  trusted. Keep HTTP on loopback; see [security and reporting](SECURITY.md).

## Documentation

| Topic | Guide |
| --- | --- |
| Setup, local MCP, ChatGPT tunnel, private HTTP | [Connections](docs/connections.md) |
| Grants, conditions, field filtering and examples | [Owner policy](docs/access-policy.md) |
| Example workout and separate write steps | [Workout workflow](docs/workouts.md) |
| Library mappings versus verified compatibility | [Capabilities](docs/capabilities.md) |
| Encryption, backups, upgrades and a missing key | [Operations and recovery](docs/operations.md) |
| Unofficial endpoints and official API options | [Garmin integration](docs/garmin-integration.md) |
| Real-account and device checks | [Manual validation](docs/manual-validation.md) |
| Docker development, checks and review rules | [Contributing](CONTRIBUTING.md) |

## Releases

Each merge to protected `main` publishes a SemVer release after its gates pass.
See [release rules and packaging](docs/releases.md) and
[GitHub Releases](https://github.com/krzysztof-gre/repbridge/releases).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) and
[third-party notices](THIRD_PARTY_NOTICES.md). No Garmin or OpenAI trademark
rights are granted.
