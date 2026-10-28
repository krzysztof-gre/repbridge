#!/bin/sh
# Run only in the built runtime image, with disposable /config and /data tmpfs.
set -eu
test "$(id -u)" = 65532
test "$(repbridge version)" = "${REPBRIDGE_EXPECTED_VERSION:-dev}"
/bin/sh /opt/repbridge/setup.sh init
test "$(wc -c < /config/vault.key | tr -d ' ')" = 32
before_key=$(sha256sum /config/vault.key)
/bin/sh /opt/repbridge/setup.sh init
test "$before_key" = "$(sha256sum /config/vault.key)"
repbridge init-access
before_access=$(sha256sum /config/mcp.key)
repbridge init-access
test "$before_access" = "$(sha256sum /config/mcp.key)"
status=$(repbridge auth status)
printf '%s\n' "$status" | grep -q '"credentialsStored":false'
printf '%s\n' "$status" | grep -q '"loginRequired":true'
repbridge catalog check
printf '%s\n' 'Runtime image smoke checks passed; no account credentials were used.'
