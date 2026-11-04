# Pinned Garmin library coverage

RepBridge covers **all 146 public domain-service methods** of the pinned
`go-garmin` library through **148 classified MCP actions**, including local
helpers. Coverage extends beyond workouts: activities and file transfers,
devices, gear, daily wellness, biometrics, body measurements, nutrition,
women's health, training plans, goals, badges/challenges, courses and golf.

These counts describe **reviewed method mappings and registered schemas**,
checked offline against the pinned library. They do not mean that every endpoint
has been exercised against a real Garmin account, that all devices support every
operation, or that Garmin authorizes this integration. Browser sign-in, token
renewal, client compatibility and watch delivery need separate operator checks;
see [manual validation](manual-validation.md) before making compatibility claims.

**Supported does not mean permitted.** Only actions allowed by the selected
owner policy are available to an assistant. New sensitive reads have no grant
in the starter policy; new writes are explicitly denied. Existing action
wildcards can cover new classified tools and should be reviewed on upgrades.

Run `policy actions` for the action catalogue and `catalog check` to validate
registered schemas without account access. Arbitrary GraphQL is a
separate privileged write and is denied by default; it cannot inherit the
resource-specific date/name guards. Credential and raw-HTTP plumbing are not
exposed as MCP actions.
