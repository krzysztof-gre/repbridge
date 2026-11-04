# Workout workflow and synthetic example

Ask your connected assistant:

> Create an `AI: Full body` strength workout with three sets of pull-ups,
> rows and leg press. Keep the rest after the final set. Show me the plan,
> then schedule it for tomorrow and queue it for my watch after I approve.

RepBridge provides the native workout schema and exercise catalogue, so the
assistant can build the payload without a separate JSON conversion format.
Delivery is queued in Garmin Connect: the watch receives it during its next sync.
Compatibility of exercises and workout types still depends on Garmin and your device.

For a small reproducible example, use [the synthetic pull-up workout](../examples/strength-workout.json):

| Workout | Sets | Reps per set | Rest after each set |
| --- | --- | --- | --- |
| `AI: Pull-ups` | 3 | 4 | 180 seconds, including the final set |

Ask the assistant to show that file's native workout payload and obtain your
approval before calling `create_workout` with it. Under the starter policy,
the creation receipt contains the permitted ID and name, for example:

```json
{"workoutId": 12345, "workoutName": "AI: Pull-ups"}
```

This receipt is illustrative; `12345` is a synthetic ID, not a recorded account
response. It confirms neither scheduling nor delivery. Schedule and queue the
returned real workout only through separate, explicitly approved calls. A queue
receipt is not proof of watch receipt; confirm it after device sync.

| Capability | Starter policy |
| --- | --- |
| Read workout library | Selected workout fields |
| Create and edit workouts | Names beginning with `AI: ` |
| Add a workout to the calendar | Existing workout name must begin with `AI: ` |
| Queue a workout for a registered device | Same name restriction; device must belong to the account |
| Find the destination device | ID, name, model and primary-training flag only |
| Read activities, health or profile data | Disabled |
| Delete workouts or change activities, courses or HR zones | Disabled |

Your MCP client must request approval for writes. A policy grant enables an
operation; it does not prove user consent. Scheduling and sending are separate
explicit tool calls, not implicit side effects of creating a workout.
