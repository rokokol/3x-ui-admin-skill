#!/usr/bin/env bash
# Refuse to ship a secret that slipped past .gitignore.
#
# .gitignore keeps a file out; this keeps a value out of a file that belongs
# here. Both are needed: the leak that matters is a real token pasted into a
# doc or a fixture, not a stray file.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
report() {
    printf 'secret-gate: %s\n' "$1" >&2
    fail=1
}

# Tracked files only — an untracked scratch file is not about to be pushed
mapfile -t tracked < <(git ls-files)
[[ ${#tracked[@]} -gt 0 ]] || {
    echo "secret-gate: nothing tracked yet" >&2
    exit 0
}

if git grep -nIE 'BEGIN (OPENSSH|RSA|EC|PGP) PRIVATE KEY' -- "${tracked[@]}" >&2; then
    report "private key material"
fi

if git grep -nIE '(github_pat_|ghp_)[A-Za-z0-9_]{20,}' -- "${tracked[@]}" >&2; then
    report "GitHub token"
fi

# The panel's session cookie, exactly as a pasted transcript would carry it
if git grep -nIE '3x-ui=[A-Za-z0-9+/_=-]{40,}' -- "${tracked[@]}" >&2; then
    report "panel session cookie"
fi

# A real value assigned to a secret-shaped key. Examples must stay placeholders
if git grep -nIE '^[[:space:]]*"?(token|password|secret|authkey|api_key)"?[[:space:]]*[=:][[:space:]]*"[^"]{8,}"' \
    -- "${tracked[@]}" | grep -vE '(replace-me|example|CHANGEME|test-|\{\{)' >&2; then
    report "literal secret assignment"
fi

# The same, unquoted: an env assignment or a shell snippet in a doc
if git grep -nIE '^[[:space:]]*(export[[:space:]]+)?(XUI_TOKEN|XUI_PIN_SHA256|TOKEN|PASSWORD|SECRET)=[A-Za-z0-9+/_=-]{16,}' \
    -- "${tracked[@]}" | grep -vE '(replace-me|example|CHANGEME|YOUR_|\.\.\.|…|\{\{)' >&2; then
    report "unquoted secret assignment"
fi

# A panel URL is a secret as soon as it carries a real host and a base path.
# Examples use a reserved name or loopback; anything else is somebody's panel
if git grep -nIoE 'https?://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9_-]{4,}' -- "${tracked[@]}" \
    | grep -vE '://(host|panel\.example|example\.com|[a-z0-9.-]*\.example|localhost|127\.0\.0\.1|github\.com|img\.shields\.io|fonts\.googleapis\.com|claude\.ai)(:|/)' \
    | grep -vE 'panel/api|/sub/|/json/' >&2; then
    report "a URL that looks like a real panel address"
fi

# secrets/ holds the panel token and URL; none of it belongs in git at all
if git ls-files | grep -qE '^secrets/'; then
    report "a file under secrets/ is tracked; that directory is the credential store"
fi

# A panel database carries every client UUID and Reality key there is
if git ls-files | grep -qE '\.db$'; then
    report "a panel database is tracked"
fi

[[ $fail -eq 0 ]] && echo "secret-gate: clean"
exit "$fail"
