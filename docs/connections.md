# Setup and assistant connections

## Quick start

**Requirements:** Docker Engine or Docker Desktop with Compose v2 and BuildKit,
and a browser on the same computer. No host Go, Python, Node or Make is required.
Use a trusted checkout or an extracted source release, then run from its root:

```sh
docker compose -f compose.quickstart.yaml run --build --rm --service-ports setup
```

This builds the application, generates a random vault key inside a dedicated
Docker volume, and prints a short-lived sign-in URL. Open that URL in a normal
Chrome window and sign in **on Garmin's page**, including OTP if requested.
Allow third-party cookies for the sign-in flow. The application never asks for
your Garmin password. Browser interaction is required; “one command” does not
bypass sign-in or account consent.

Only run one sign-in container at a time: it uses `127.0.0.1:8787`. If that port
is occupied, stop the earlier login attempt. For a remote Docker host, forward port 8787 to your computer with
`ssh -N -L 8787:127.0.0.1:8787 user@server`, then open the printed URL locally.

The new-install project is named `repbridge`, with separate key and token
volumes. It does not reuse an existing legacy `repbridge-data` vault. **Existing
users and NAS deployments:** keep using your current Compose configuration;
preserve the exact key, volume, Compose project identity and tunnel settings
when upgrading. Renaming a project creates different named volumes.

## Connect an assistant

### Local MCP clients

Add this server to a client that supports stdio MCP. Replace `/path/to/repbridge`
with the absolute checkout path; see the [copyable example](../examples/mcp-client.json).

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

Let the client launch the process. Running it manually waits for MCP requests
on stdin. Do not add a TTY. Configure the client to require approval for writes.
Start with `get_permissions` and `garmin_session_status`, then read your workout
library before creating anything.

### ChatGPT through an OpenAI tunnel

The optional gateway embeds the official OpenAI tunnel client. The Docker host
must stay online. It needs outbound connectivity, a tunnel associated with your
ChatGPT account/workspace, and a restricted runtime key. No inbound port or
running Codex app is required. Account and mobile availability are controlled
by OpenAI; confirm a real tool call on your intended ChatGPT surface.

1. Create a tunnel in OpenAI Platform and associate it only with the intended
   ChatGPT account/workspace. Follow the official
   [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
2. Create a restricted runtime key with the required tunnel Read and Use access.
   Store it through the hidden Docker terminal prompt:

   ```sh
   docker compose -f compose.quickstart.yaml run --rm -it setup runtime-key
   ```

3. Set `REPBRIDGE_OPENAI_TUNNEL_ID` to your tunnel ID in the shell or a local
   Compose environment file. This ID is configuration; the runtime key belongs
   only in the hidden prompt, never chat, command arguments or an environment file.
4. Check configuration, start the gateway and inspect its connection log:

   ```sh
   docker compose -f compose.quickstart.yaml run --rm openai-gateway gateway check
   docker compose -f compose.quickstart.yaml up -d openai-gateway
   docker compose -f compose.quickstart.yaml logs --tail=30 openai-gateway
   ```

5. Install the custom MCP integration in ChatGPT using that tunnel. Restrict it
   to the owner and require approval for writes. Ask it to call `get_permissions`,
   `garmin_session_status` and `list_workouts`, then repeat on your phone.

`gateway check` is offline and reports `connectionVerified: false`. A successful
poll confirms the transport; a successful ChatGPT tool call confirms the complete
connection. Neither proves a workout has reached a watch.

### Authenticated HTTP

A separate bearer key protects the loopback-only endpoint:

```sh
docker compose -f compose.quickstart.yaml run --rm init-access
docker compose -f compose.quickstart.yaml up -d mcp-http
```

Configure your MCP client's secret store with the generated `/config/mcp.key`
from the key volume. Endpoint: `http://127.0.0.1:8788/mcp`. Keep it on loopback;
public ingress requires HTTPS and an established authorization provider.
