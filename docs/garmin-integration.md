# Garmin integration boundary and official alternatives

RepBridge currently uses the pinned `go-garmin` client and a small browser-ticket
exchange against unofficial Garmin endpoints. The exchange uses Garmin mobile
client identifiers and a mobile User-Agent; it is not an application registration
or an authorization granted to RepBridge by Garmin. Keeping the code open source
does not establish permission to use those endpoints. Changes to Garmin services
can break sign-in or operations without a compatible RepBridge release.

Garmin's [Personal API](https://developer.garmin.com/gc-developer-program/personal/personal-faq)
offers individual access to one's own data using a self-generated API key.
The [official program overview](https://developer.garmin.com/gc-developer-program/overview/)
lists activity, health and women's-health reads for Personal, and a Training API
under Business. The documented Personal scope does not list the workout-write
flow used here; do not assume the two interfaces are interchangeable. RepBridge
does not currently implement either official API.

The current integration preserves the upstream native workout operations and
token-refresh behavior. Before advertising broader compatibility or building
a multi-user service, review the applicable Garmin terms for the service,
account and region, assess official API coverage and access requirements, and
record the integration decision in the [launch tracking issue](https://github.com/krzysztof-gre/repbridge/issues/6). This documentation
does not claim that the unofficial flow complies with those terms. Official API
migration needs its own reviewed authentication and capability design.
