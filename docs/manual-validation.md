# Manual release validation

Use this checklist for a specific release, deployment and client. Offline tests
establish behavior against fixtures; catalogue checks establish method/schema
coverage. Neither proves that Garmin's live endpoints, browser sign-in, a
particular ChatGPT surface or a watch work with that release.

This is a procedure, not a completed test report. Track outstanding checks in
the [launch issue](https://github.com/krzysztof-gre/repbridge/issues/6). Publish only
sanitized outcomes in issue or release discussions. Keep account evidence,
local deployment files and historical notes under ignored `.private/` with
private permissions, never in committed reports or screenshots.

## Before account operations

1. The account owner chooses the target deployment and explicitly approves any
   sign-in, credential refresh and write operation. Run checks manually, never
   from CI or the default test target.
2. Record the source commit or immutable release/image digest, host OS and CPU
   architecture, Docker/Compose versions, browser version, MCP client/version
   and policy version. Record device model/firmware only, not account or device IDs.
3. Read [the integration boundary](garmin-integration.md), review the Garmin terms
   applicable to the service/account/region and record the integration decision
   without publishing private contract or account material. Assess the official
   Personal/Business options before making broader compatibility claims.
4. Use the existing deployment's exact Compose project, key and token volumes
   when testing an upgrade. Securely back up the matching vault/key before
   changing an existing deployment. Never copy active tokens into a second
   running deployment or use a newly generated key to open an old vault.
5. For a new-install check, deliberately select a fresh deployment with no
   personal exports or preexisting credentials. Follow [setup](connections.md).
   Do not remove an existing deployment's volumes as test cleanup.

## Checks and evidence

Record each result as **passed**, **failed** or **not checked**, with the release,
environment and a bounded observation. A skipped check stays not checked.

| Check | Required observation |
| --- | --- |
| Clean installation | Docker builds/starts with the documented command; a new key and token volume remain separate. No host runtime is needed. |
| Browser sign-in and OTP | The short-lived loopback page loads; credentials and OTP are entered on Garmin's origin; CLI reports completion without printing secrets. |
| Stored session | Credential-free status changes after sign-in. This alone does not prove remote validity. |
| Manual refresh | After owner approval, `auth refresh` succeeds; a subsequent permitted read succeeds and no credential material appears in logs. |
| Automatic refresh | After a real renewal opportunity, a permitted operation succeeds and a new process can reuse the stored session. If no renewal was observed, leave not checked. |
| MCP discovery/read | On each advertised client, `get_permissions`, `garmin_session_status` and permitted workout reads succeed with only selected fields. |
| Workout creation | The client shows the native payload and gets approval; the synthetic `AI: Pull-ups` example creates one workout with the expected sets/rests. |
| Workout replacement | After separate approval, an allowed test workout is replaced and its fetched name and steps match the reviewed payload. |
| Calendar scheduling | After separate approval and agreement on the calendar date, the test workout appears on that date in Garmin Connect. |
| Device queue | After separate approval and selection of the owner's intended device, queueing returns a permitted receipt. This is not device delivery. |
| Watch receipt | After the real device syncs, inspect the workout on the intended watch and verify its steps/rests. A queue receipt or tunnel log cannot satisfy this row. |
| Upgrade/restart | Existing key/vault and policy are preserved; a fresh MCP process can perform a permitted read after restart. |

Use [the synthetic example](workouts.md), reviewed before each write. Do not use
someone's existing workout as a negative authorization test. Offline security
fixtures cover rejected names, dates, fields and denied operations without
probing unrelated account data.

For an interrupted or failed write, inspect permitted reads before any retry.
The write might have committed even if no response reached the client. Clean up
test workouts manually in Garmin Connect only when the owner requests it;
deletion is denied by the starter policy.

## ChatGPT and client compatibility

For the optional gateway, record these checkpoints separately:

1. Offline `gateway check`: configuration valid, `connectionVerified: false`.
2. First authenticated tunnel poll: transport reached OpenAI, not a ChatGPT call.
3. A real `get_permissions` and a representative permitted read from the intended
   ChatGPT account/workspace and surface: confirms that surface's tool connection.
4. Repeat on the intended phone app/version if mobile support will be advertised.

Keep the tunnel restricted to the owner/workspace. Do not infer mobile support
from a desktop call, or workout delivery from any tunnel checkpoint. Record
policy/schema mapping, live API behavior, client compatibility and device sync
as separate outcomes. Qualify public claims to match the observations.
