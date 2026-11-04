# Owner access policy

**The owner policy is the boundary between an assistant and your Garmin account.**
RepBridge evaluates it on the server for every tool invocation and filters the
response before returning data to the client. The same rules apply to local MCP,
authenticated HTTP and the OpenAI gateway. A model instruction, a guessed tool name,
or a caller-supplied workout name/date cannot override the policy.

You can independently control:

| Control | Policy element | Example |
| --- | --- | --- |
| Which operations may run | `Action` and `Effect` | Allow workout creation; deny deletion |
| Which workouts may be changed | `Condition` with `StringLike` or `StringEquals` | Only names matching `AI: *` |
| Which activity history may be read | `Condition` with date operators | Only activities starting on/after a chosen instant |
| Which response fields the assistant sees | `Fields` using JSON Pointers | Return distance and duration, omit GPS and heart rate |

### How decisions work

1. **Default deny:** an action needs a matching `Allow`. Unclassified tools and
   actions without a grant remain unavailable.
2. **Conditions must match:** the server evaluates supported attributes against
   validated workout input or trusted Garmin metadata. Caller assertions do not
   authorize access.
3. **Explicit Deny wins:** any matching `Deny` blocks the whole action, even when
   another statement allows it. Statement order does not change this.
4. **Response projection:** successful results contain only fields granted by
   matching Allows. Multiple matching Allows combine their fields; a broad
   `Fields: ["*"]` grant can widen disclosure.

These rules are enforced in code. MCP tools cannot edit the policy. Human
approval is an additional responsibility of the MCP client: a policy grant
alone is not proof that a user approved a write.

### Example 1: create and edit only AI-prefixed workouts

This complete policy allows two operations and returns only an ID/name receipt:

```json
{
  "Version": "2026-10-20",
  "Statement": [
    {
      "Sid": "CreateAndEditAIWorkouts",
      "Effect": "Allow",
      "Action": ["garmin:create_workout", "garmin:update_workout"],
      "Resource": "*",
      "Fields": ["/workoutId", "/workoutName"],
      "Condition": {
        "StringLike": {
          "garmin:WorkoutName": ["AI: *"]
        }
      }
    }
  ]
}
```

- `AI: Full body` matches; `Full body`, `ai: Full body` and leading-space
  variants do not. Matching is case sensitive; `*` matches any sequence.
- Creation checks the actual native `workout.workoutName` submitted to Garmin.
- Editing checks **both the fetched existing name and the replacement name**.
  An assistant cannot gain access to an unrelated workout by renaming it into
  the allowed prefix, or remove the prefix from an allowed workout.
- This policy grants no workout reads, calendar scheduling, device delivery,
  activity reads or helper tools. Add those explicitly when needed, or adapt
  the more complete [starter policy](../policies/starter.json).

To restrict scheduling or delivery in the same way, the supported actions are
`garmin:schedule_workout` and `garmin:push_workout_to_device`. Both check the
existing workout's name; delivery also verifies that the device belongs to the
account. Their response fields need their own appropriate grant.

### Example 2: recent activity summaries, without GPS or heart rate

This complete read-only policy returns a small selection of summary fields and
sets a hard lower bound on activity history:

```json
{
  "Version": "2026-10-20",
  "Statement": [
    {
      "Sid": "ReadActivitySummaries",
      "Effect": "Allow",
      "Action": ["garmin:list_activities"],
      "Resource": "*",
      "Fields": ["/activityId", "/activityName", "/distance", "/duration"]
    },
    {
      "Sid": "DenyEarlierActivityHistory",
      "Effect": "Deny",
      "Action": ["garmin:list_activities", "garmin:get_activity*"],
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "garmin:ActivityStartTime": ["2026-10-15T00:00:00+02:00"]
        }
      }
    }
  ]
}
```

- Starts **at or after** the boundary are eligible. The timestamp is midnight
  in Warsaw on 15 October 2026; comparisons use the actual instant and explicit
  offset, not a date string or the activity's name.
- The server obtains the start time from Garmin UTC metadata. Missing, invalid
  or conflicting metadata fails closed. The caller cannot supply a newer date
  to unlock an old activity.
- Each list item is filtered by date and then projected to the four allowed
  fields. GPS coordinates, heart rate, calories and other unselected fields
  are not returned. Personal information written into an allowed field such
  as `activityName` is still disclosed.
- Detail tools have **no Allow** here. The `garmin:get_activity*` Deny also
  preserves the history boundary if you later grant a classified detail tool.
  Action wildcards cover explicitly classified tools, not arbitrary endpoints.
- Garmin pagination offsets are preserved: a page may become short or empty
  after filtering. No older records are disclosed to explain omissions.

**To narrow an existing policy, replace its broader activity Allow.** Adding
this four-field Allow beside an existing `Fields: ["*"]` Allow does not remove
that broader disclosure. If you deliberately choose `Fields: ["*"]`, you grant
all returned fields for eligible records, including sensitive fields Garmin
returns. The activity-date and workout-name restrictions do not redact those fields.

### Example 3: make workout deletion an explicit prohibition

Add this statement to the `Statement` array of an existing policy:

```json
{
  "Sid": "NeverDeleteWorkouts",
  "Effect": "Deny",
  "Action": ["garmin:delete_workout"],
  "Resource": "*"
}
```

Without an Allow, deletion is already denied by default. This explicit Deny
keeps it blocked even if a later statement grants a wider action pattern.
An Allow cannot override it; the owner must remove the Deny deliberately to
enable deletion. Deny statements block whole actions and do not take `Fields`.
A date-conditioned Deny, as in example 2, applies only when its condition matches.

### Apply and inspect your policy

The quick start loads [`policies/starter.json`](../policies/starter.json). It permits
AI-prefixed workout management, scheduling/delivery and minimal device discovery;
activity and health reads are disabled. `policies/default.json` carries the same grants for file-mounted deployments.

The first two examples above are independent complete policies; the third is a
statement to insert into one. They illustrate different grants and are not
instructions to append every example to the starter policy. Retain or add
helper/read grants only when you intend to expose those capabilities.

Edit the selected policy file as the owner, validate it, and restart every MCP
process that uses it:

```sh
docker compose -f compose.quickstart.yaml run --rm repbridge policy check
docker compose -f compose.quickstart.yaml run --rm repbridge policy actions
docker compose -f compose.quickstart.yaml run --rm repbridge policy explain --action garmin:create_workout --workout-name 'AI: Full body'
docker compose -f compose.quickstart.yaml run --rm repbridge policy explain --action garmin:delete_workout
docker compose -f compose.quickstart.yaml restart openai-gateway
```

`policy explain` simulates the **currently mounted policy** without a Garmin
call; hypothetical names/dates do not authorize real MCP operations. Restart
`mcp-http` too if used, and let local stdio clients restart their child
containers. A permitted `get_permissions` call reports the active process policy.
Protect the policy directory from other filesystem tools available to a model:
a process with host write access can act as an operator.

### IAM-inspired scope

RepBridge implements a documented subset inspired by IAM: action patterns,
Allow/Deny precedence, field projection and selected string/date conditions.
It is **not AWS IAM compatible**. `Resource` must currently be `"*"`; there are
no IAM roles, principals, account federation or per-ID ARN rules. One deployment
connects to one Garmin account and shares one owner policy across its delegates.
Supported operators are `StringEquals`, `StringLike`, `DateEquals`,
`DateNotEquals`, `DateLessThan`, `DateLessThanEquals`, `DateGreaterThan` and
`DateGreaterThanEquals`. Keys/operators combine with AND; values within one
condition combine with OR. Workout-name conditions apply only to classified
workout operations; date conditions apply only to classified activity readers.
Unsupported combinations, duplicate JSON keys and unknown syntax reject startup.

`Fields` uses JSON Pointers: `/laps/*/distance` selects distances within an array;
`~1` escapes `/` and `~0` escapes `~` in a key. Selecting a parent grants its entire
subtree, including future children. Binary exports need a whole-file grant and
cannot be filtered inside FIT/GPX/ZIP bytes. Date rules do not constrain unrelated
calendar, wellness or aggregate tools: those need separate grants.
