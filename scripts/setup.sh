#!/bin/sh
# Runs inside Docker as the application user. Never prints secret contents.
set -eu
umask 077
config=/config
key="$config/vault.key"
if [ -L "$config" ] || [ ! -d "$config" ]; then
    echo 'The key volume must be a real directory.' >&2; exit 1
fi
chmod 0700 "$config"
case "${1:-login}" in
    login|init)
        if [ -e "$key" ] || [ -L "$key" ]; then
            test ! -L "$key" && test -f "$key" && test "$(wc -c < "$key" | tr -d ' ')" = 32 || {
                echo 'Existing vault key is invalid; left unchanged.' >&2; exit 1;
            }
        else
            temp=$(mktemp "$config/.vault-key.XXXXXX")
            trap 'rm -f "$temp"' EXIT HUP INT TERM
            dd if=/dev/urandom of="$temp" bs=32 count=1 2>/dev/null
            test "$(wc -c < "$temp" | tr -d ' ')" = 32
            chmod 0600 "$temp"
            ln "$temp" "$key"
            rm -f "$temp"
            trap - EXIT HUP INT TERM
        fi
        chmod 0600 "$key"
        echo 'Vault key ready; its contents were not displayed.'
        if [ "${1:-login}" = init ]; then exit 0; fi
        exec /usr/local/bin/repbridge auth login
        ;;
    runtime-key)
        test -t 0 || { echo 'Use an interactive terminal (-it).' >&2; exit 1; }
        test ! -e "$config/openai-runtime.key" && test ! -L "$config/openai-runtime.key" || {
            echo 'Runtime key already exists; remove it deliberately before replacement.' >&2; exit 1;
        }
        temp=$(mktemp "$config/.runtime-key.XXXXXX")
        saved_tty=$(stty -g)
        trap 'stty "$saved_tty"; rm -f "$temp"' EXIT HUP INT TERM
        printf 'Restricted OpenAI tunnel runtime key (hidden): '
        stty -echo
        IFS= read -r runtime_key
        stty "$saved_tty"
        printf '\n'
        test -n "$runtime_key" && test "${#runtime_key}" -le 4096
        printf '%s' "$runtime_key" > "$temp"
        unset runtime_key
        chmod 0600 "$temp"
        ln "$temp" "$config/openai-runtime.key"
        rm -f "$temp"
        trap - EXIT HUP INT TERM
        echo 'Runtime key stored; its contents were not displayed.'
        ;;
    *) echo 'Usage: setup [login|init|runtime-key]' >&2; exit 1 ;;
esac
