# Garmin access control

An owner delegates selected Garmin Connect capabilities to a model through an
MCP server. The owner's access policy limits both actions and returned data.

## Language

**Owner**: The person controlling the connected Garmin account and its access
policy. _Avoid_: Tenant, model user.

**Action**: A named capability corresponding to exactly one registered MCP tool.
_Avoid_: Endpoint permission, prompt instruction.

**Access policy**: The owner's rules granting or denying actions and selecting
the response fields a caller may receive. _Avoid_: System prompt, consent flag.

**Response field**: A path in Garmin data whose value the owner may disclose to
the caller. Selecting a parent field deliberately discloses its entire subtree.

**Workout name condition**: A rule matching the actual name of a workout before
a permitted operation can act on it. _Avoid_: Model-declared permission.
