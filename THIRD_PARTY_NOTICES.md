# Third-party software

RepBridge source, documentation and wordmark are licensed under Apache-2.0.
Dependencies retain their original licenses. The exact versions are in `go.mod`
and `go.sum`; this document does not relicense any dependency.

Garmin domain behavior is provided by
[ndeloof/go-garmin](https://github.com/ndeloof/go-garmin), Apache-2.0, pinned in
`go.mod`. We use its API and MCP interfaces, rather than copying its implementation.
The MCP and tunnel transports use the official Go SDKs listed in `go.mod`.

Every application image includes the Go license, module inventory and available
root LICENSE/COPYING/NOTICE/COPYRIGHT texts for Go modules linked into the application at
`/usr/share/licenses/repbridge/dependencies`. A build fails when a linked module has no
root license text: review it before distribution. Alpine packages retain their
own distribution licenses; Alpine's installed package inventory is available
inside the image through `apk info`. Do not remove upstream notices when
redistributing images or adding vendored code.

Source archives include this notice and the project's license. They reference
pinned dependencies rather than bundling third-party source. They do not
include a prebuilt application. A source archive is not an SBOM or a security
scan of a built image.
