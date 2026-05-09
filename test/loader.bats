#!/usr/bin/env bats
# Regression tests for direnvrc — the recursive .envrc loader.
#
# Each test creates an isolated $XDG_DATA_HOME / $XDG_CONFIG_HOME under
# $BATS_TEST_TMPDIR so direnv's allow/deny state and direnv.toml are
# scoped to one test. Sources direnvrc as a library
# (DIRENV_RECURSIVE_LIB_ONLY=1) so the trailing _direnv_recursive_load
# does not fire — we drive individual functions directly.

setup() {
    DIRENVRC="$BATS_TEST_DIRNAME/../direnvrc"
    [[ -f $DIRENVRC ]] || { echo "direnvrc not found at $DIRENVRC" >&2; return 1; }

    export XDG_DATA_HOME="$BATS_TEST_TMPDIR/share"
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_DATA_HOME/direnv/allow" \
             "$XDG_DATA_HOME/direnv/deny" \
             "$XDG_CONFIG_HOME/direnv"

    export DIRENV_RECURSIVE_LIB_ONLY=1
    export DIRENV_RECURSIVE_QUIET=1
    # shellcheck disable=SC1090
    source "$DIRENVRC"
}

# F1 — TOML key disambiguation regression.
#
# direnvrc:140-141 used a substring test to pick the key, so an
# `exact` entry whose value contains the literal "prefix" was silently
# reclassified as a `prefix` entry. Combined with HasPrefix-style
# matching, that grants directory-prefix trust the user never wrote.
#
# Pre-fix: _in_toml_whitelist authorises a sibling path that shares the
# entry as a string prefix (because the entry was treated as `prefix =
# ["/.../api-prefix"]` and HasPrefix-style matched). Post-fix: refused.
@test "F1: exact entry containing 'prefix' substring is not reclassified as prefix" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<EOF
[whitelist]
exact = ["/tmp/F1-fixture/api-prefix"]
EOF

    # Sibling path that shares the entry as a STRING prefix but is not
    # the same directory. Pre-fix: bash `[[ $f == "$entry"* ]]` matches
    # because the entry was reclassified to prefix. Post-fix: refused.
    run _direnv_recursive_in_toml_whitelist "/tmp/F1-fixture/api-prefix-evil/.envrc"
    [ "$status" -ne 0 ]

    # The exact entry's `.envrc` MUST still match — direnv.toml(1) says
    # directory entries are equivalent to <dir>/.envrc.
    run _direnv_recursive_in_toml_whitelist "/tmp/F1-fixture/api-prefix/.envrc"
    [ "$status" -eq 0 ]
}

# F2 — empty-hash auto-allow regression.
#
# direnvrc:118-122 did `[[ -e "$datadir/allow/$h" ]]` without
# validating $h. If the sha256 pipeline returns 0 with empty stdout
# (broken or stub sha256sum), the test resolves to `[[ -e $datadir/allow/ ]]`
# — the directory itself — and every ancestor auto-loads.
#
# Pre-fix: _is_allowed_by_db returns 0 for any path. Post-fix: returns
# non-zero because the empty digest is rejected at the source.
@test "F2: empty sha256 output does not authorize via the allow directory" {
    # Override the hash function to simulate a broken sha256 tool that
    # exits 0 with no output. Mirrors the failure mode H3 documents.
    _direnv_recursive_sha256() { return 0; }

    local fixture="$BATS_TEST_TMPDIR/.envrc"
    echo 'export FOO=bar' > "$fixture"

    run _direnv_recursive_is_allowed_by_db "$fixture"
    [ "$status" -ne 0 ]
}

# F2 (companion) — even with the empty-digest guard, a real sha256 hash
# that doesn't appear in the allow database must not authorise.
@test "F2 companion: unallowed file is not authorized via allow-db" {
    local fixture="$BATS_TEST_TMPDIR/.envrc"
    echo 'export FOO=bar' > "$fixture"

    run _direnv_recursive_is_allowed_by_db "$fixture"
    [ "$status" -ne 0 ]
}

# Positive control: a file whose content hash is in allow/ IS authorised.
# Guards against over-zealous fixes that break the legitimate path.
@test "F2 positive control: allow-db hit authorizes" {
    local fixture="$BATS_TEST_TMPDIR/.envrc"
    echo 'export FOO=bar' > "$fixture"
    local h
    h=$({ printf '%s\n' "$fixture"; cat "$fixture"; } | sha256sum | awk '{print $1}')
    touch "$XDG_DATA_HOME/direnv/allow/$h"

    run _direnv_recursive_is_allowed_by_db "$fixture"
    [ "$status" -eq 0 ]
}

# F3 — tilde expansion in TOML whitelist entries.
#
# direnv (config.go:expandTildePath) rewrites a leading `~/` to $HOME for
# both prefix and exact entries. Without expansion in the bash mirror, an
# entry like `prefix = ["~/work"]` is compared literally against absolute
# walker paths and never matches. Users with the documented
# direnv-portable form silently lose ancestor authorisation.
@test "F3: prefix entry with leading ~ matches an absolute path under \$HOME" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<EOF
[whitelist]
prefix = ["~/F3-fixture-prefix"]
EOF

    run _direnv_recursive_in_toml_whitelist "$HOME/F3-fixture-prefix/sub/.envrc"
    [ "$status" -eq 0 ]
}

@test "F3: exact entry with leading ~ matches \$HOME-based path" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<EOF
[whitelist]
exact = ["~/F3-fixture-exact"]
EOF

    # direnv.toml(1): a directory entry matches <dir>/.envrc.
    run _direnv_recursive_in_toml_whitelist "$HOME/F3-fixture-exact/.envrc"
    [ "$status" -eq 0 ]
}

# Negative control: literal ~ that is NOT a leading ~/ must not be
# expanded — direnv only expands the leading form.
@test "F3 negative control: literal '~' inside a path is not expanded" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<EOF
[whitelist]
prefix = ["/tmp/has~mid"]
EOF

    run _direnv_recursive_in_toml_whitelist "/tmp/has~mid/.envrc"
    [ "$status" -eq 0 ]
}

# F11 — path canonicalisation parity with Go's filepath.Clean.
#
# The walker normally produces clean paths via dirname, but a poisoned
# $PWD (or any caller passing a non-canonical path) needs to be cleaned
# before hashing — otherwise the digest diverges from `direnv allow`'s.
#
# direnv (filepath.Abs) calls Clean: collapses //, removes . segments,
# resolves .. segments, drops trailing /. Mirror that here.
@test "F11: abs eliminates '.' segments" {
    run _direnv_recursive_abs "/a/./b/.envrc"
    [ "$status" -eq 0 ]
    [ "$output" = "/a/b/.envrc" ]
}

@test "F11: abs resolves '..' segments" {
    run _direnv_recursive_abs "/a/b/../c/.envrc"
    [ "$status" -eq 0 ]
    [ "$output" = "/a/c/.envrc" ]
}

@test "F11: abs collapses '//' segments" {
    run _direnv_recursive_abs "//a//b//.envrc"
    [ "$status" -eq 0 ]
    [ "$output" = "/a/b/.envrc" ]
}

@test "F11: abs drops trailing slash" {
    run _direnv_recursive_abs "/a/b/"
    [ "$status" -eq 0 ]
    [ "$output" = "/a/b" ]
}

@test "F11: abs leaves clean paths unchanged" {
    run _direnv_recursive_abs "/a/b/.envrc"
    [ "$status" -eq 0 ]
    [ "$output" = "/a/b/.envrc" ]
}

@test "F11: abs handles root edge case" {
    run _direnv_recursive_abs "/"
    [ "$status" -eq 0 ]
    [ "$output" = "/" ]
}

# F13 — unclosed TOML array silently accepted.
#
# A truncated direnv.toml (mid-write, disk full) leaves the array open.
# direnv (BurntSushi/toml) errors out and refuses to load any whitelist.
# Pre-fix: bash awk parser emits whatever entries it accumulated.
# Post-fix: emit nothing (fail-closed).
@test "F13: unclosed TOML array yields no whitelist entries" {
    # Note: no closing ]
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<EOF
[whitelist]
prefix = ["/F13-never-closed"
EOF
    run _direnv_recursive_in_toml_whitelist "/F13-never-closed/sub/.envrc"
    [ "$status" -ne 0 ]
}

# Closed array control: same fixture but with the closing ] — must still
# match. Guards against the F13 fix being too aggressive.
@test "F13 control: closed TOML array still matches" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<EOF
[whitelist]
prefix = ["/F13-closed"]
EOF
    run _direnv_recursive_in_toml_whitelist "/F13-closed/sub/.envrc"
    [ "$status" -eq 0 ]
}

# F14 — operational logging: warnings must bypass DIRENV_RECURSIVE_QUIET.
#
# QUIET is documented to silence routine load/skip noise. Errors and
# warnings are operational diagnostics — they must always reach the
# operator. Split _log into _log_status (suppressed by QUIET) and
# _log_warn (always emits).
@test "F14: log_status is silenced by DIRENV_RECURSIVE_QUIET" {
    DIRENV_RECURSIVE_QUIET=1
    output=$(_direnv_recursive_log_status "routine message" 2>&1)
    [ -z "$output" ]
}

@test "F14: log_warn bypasses DIRENV_RECURSIVE_QUIET" {
    DIRENV_RECURSIVE_QUIET=1
    output=$(_direnv_recursive_log_warn "diagnostic message" 2>&1)
    [[ "$output" == *"diagnostic message"* ]]
}

@test "F14: log_status emits when QUIET is unset" {
    unset DIRENV_RECURSIVE_QUIET
    output=$(_direnv_recursive_log_status "routine message" 2>&1)
    [[ "$output" == *"routine message"* ]]
}

# DIRENV_RECURSIVE_DEPTH — depth knob (replaces DIRENV_RECURSIVE_CEILING).
# Ship-default is OFF — users opt in by setting a positive integer in
# their shell rc.
#   unset / empty / 0  -> off (no ancestors emitted)
#   N (positive)       -> walk at most N parent directories above $PWD
#   non-numeric        -> off + warn (fail-closed)
@test "F-DEPTH: unset means off (loader inert by default)" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a/b/c"
    echo 'x' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    echo 'x' > "$BATS_TEST_TMPDIR/d/a/b/.envrc"
    cd "$BATS_TEST_TMPDIR/d/a/b/c"
    unset DIRENV_RECURSIVE_DEPTH
    local out
    out=$(_direnv_recursive_walk)
    [ -z "$out" ]
}

@test "F-DEPTH: 0 emits no ancestors" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a/b/c"
    echo 'x' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    echo 'x' > "$BATS_TEST_TMPDIR/d/a/b/.envrc"
    cd "$BATS_TEST_TMPDIR/d/a/b/c"
    DIRENV_RECURSIVE_DEPTH=0
    local out
    out=$(_direnv_recursive_walk)
    [ -z "$out" ]
}

@test "F-DEPTH: N=1 walks exactly one parent" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a/b/c"
    echo 'outer' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    echo 'mid'   > "$BATS_TEST_TMPDIR/d/a/b/.envrc"
    echo 'inner' > "$BATS_TEST_TMPDIR/d/a/b/c/.envrc"
    cd "$BATS_TEST_TMPDIR/d/a/b/c"
    DIRENV_RECURSIVE_DEPTH=1
    local out
    out=$(_direnv_recursive_walk)
    # One line; the closest ancestor (a/b/.envrc), not a/.envrc.
    # PWD's own .envrc (c/.envrc) is dropped — direnv loads it natively.
    [ "$(printf '%s\n' "$out" | grep -c '/.envrc$')" -eq 1 ]
    [[ "$out" == *"/d/a/b/.envrc"* ]]
}

@test "F-DEPTH: N=5 caps even when fewer ancestors exist" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a/b"
    echo 'outer' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    echo 'inner' > "$BATS_TEST_TMPDIR/d/a/b/.envrc"
    cd "$BATS_TEST_TMPDIR/d/a/b"
    DIRENV_RECURSIVE_DEPTH=5
    local out
    out=$(_direnv_recursive_walk)
    # Walker returns a/.envrc; b/.envrc is PWD's own and dropped.
    [ "$(printf '%s\n' "$out" | grep -c '/.envrc$')" -eq 1 ]
    [[ "$out" == *"/d/a/.envrc"* ]]
}

@test "F-DEPTH: non-numeric value fails closed (treated as 0)" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a/b"
    echo 'x' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    cd "$BATS_TEST_TMPDIR/d/a/b"
    DIRENV_RECURSIVE_DEPTH=banana
    local out
    out=$(_direnv_recursive_walk)
    [ -z "$out" ]
}

# F4 — TOML parser must handle real-world shapes the regex parser mangled.
# Each fixture exercises one shape from the emergent-agent corpus.

@test "F4: ']' inside a quoted string survives the parser" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
[whitelist]
exact = ["/F4/has]bracket/.envrc"]
EOF
    run _direnv_recursive_in_toml_whitelist "/F4/has]bracket/.envrc"
    [ "$status" -eq 0 ]
}

@test "F4: ',' inside a quoted string survives the parser" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
[whitelist]
exact = ["/F4/has,comma/.envrc"]
EOF
    run _direnv_recursive_in_toml_whitelist "/F4/has,comma/.envrc"
    [ "$status" -eq 0 ]
}

@test "F4: '#' inside a quoted string survives the parser" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
[whitelist]
exact = ["/F4/has#hash/.envrc"]
prefix = ["/F4/normal"]
EOF
    # The hash entry survives, AND the next key isn't corrupted by bleed.
    run _direnv_recursive_in_toml_whitelist "/F4/has#hash/.envrc"
    [ "$status" -eq 0 ]
    run _direnv_recursive_in_toml_whitelist "/F4/normal/sub/.envrc"
    [ "$status" -eq 0 ]
}

@test "F4: TOML literal-string entries match without retaining quotes" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
[whitelist]
exact = ['/F4/literal-string/.envrc']
EOF
    run _direnv_recursive_in_toml_whitelist "/F4/literal-string/.envrc"
    [ "$status" -eq 0 ]
}

@test "F4: TOML basic-string escapes are interpreted (\\\" -> \")" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
[whitelist]
exact = ["/F4/has\"quote/.envrc"]
EOF
    run _direnv_recursive_in_toml_whitelist '/F4/has"quote/.envrc'
    [ "$status" -eq 0 ]
}

@test "F4: inline-table whitelist form is recognised" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
whitelist = { prefix = ["/F4/inline"] }
EOF
    run _direnv_recursive_in_toml_whitelist "/F4/inline/sub/.envrc"
    [ "$status" -eq 0 ]
}

@test "F4: duplicate [whitelist] table fails closed (no entries)" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
[whitelist]
prefix = ["/F4/first"]

[whitelist]
prefix = ["/F4/second"]
EOF
    # TOML spec violation — real parser errors. Loader must reject the
    # whole config (no entries trusted).
    run _direnv_recursive_in_toml_whitelist "/F4/first/sub/.envrc"
    [ "$status" -ne 0 ]
    run _direnv_recursive_in_toml_whitelist "/F4/second/sub/.envrc"
    [ "$status" -ne 0 ]
}

@test "F4: invalid TOML fails closed (no entries)" {
    cat > "$XDG_CONFIG_HOME/direnv/direnv.toml" <<'EOF'
this is not valid toml ===
EOF
    run _direnv_recursive_in_toml_whitelist "/anything/.envrc"
    [ "$status" -ne 0 ]
}

# F6 — direnvrc must not override direnv stdlib's source_up family.
#
# Earlier revisions replaced source_up / source_up_if_exists with no-ops
# to avoid double-loading parents. That broke the stdlib's contract for
# legacy .envrc files written for the standard model — `source_up ||
# fallback` patterns silently took the success branch. Decision: leave
# the stdlib functions alone; double-loading is the .envrc author's
# concern (most direnv idioms are idempotent).
@test "F6: direnvrc does not redefine source_up" {
    # Stand in as direnv stdlib by defining source_up before re-sourcing.
    source_up() { return 42; }
    source_up_if_exists() { return 43; }

    # Re-source direnvrc with stubs in place. Sentinel return codes are
    # preserved if and only if direnvrc did not redefine the functions.
    DIRENV_RECURSIVE_LIB_ONLY=1
    # shellcheck disable=SC1090
    source "$DIRENVRC"

    run source_up
    [ "$status" -eq 42 ]
    run source_up_if_exists
    [ "$status" -eq 43 ]
}

# F12 — path containing a tab is silently truncated by IFS=\t read.
#
# The TOML parser emits "key\tentry"; the consumer splits on tab via
# IFS=\$'\\t'. A path containing a tab loses everything after the second
# tab, silently producing the wrong (shorter) entry. Pre-fix:
# truncated entry never matches any real path → fail-closed but
# silent. Post-fix (NUL delimiter or alternate transport): full
# entry survives.
@test "F12: tab character in a path is preserved through parser+consumer" {
    # Write a TOML entry with a literal tab in the path. Use printf to
    # embed the tab so the heredoc doesn't get clever about whitespace.
    printf '[whitelist]\nexact = ["/tmp/F12-fixture\twith-tab"]\n' \
        > "$XDG_CONFIG_HOME/direnv/direnv.toml"

    # The real entry is `/tmp/F12-fixture\twith-tab` (a directory).
    # direnv.toml(1) treats directory entries as `<dir>/.envrc`.
    run _direnv_recursive_in_toml_whitelist $'/tmp/F12-fixture\twith-tab/.envrc'
    [ "$status" -eq 0 ]
}

# F-DROP — the walker must exclude the .envrc that direnv natively loads.
#
# direnv (FindRC -> findEnvUp -> findUp, internal/cmd/rc.go) walks up from
# $PWD and loads the FIRST .envrc found as the active RC. The walker's
# job is to load the ADDITIONAL ancestors above that one. So whichever
# .envrc is innermost in our chain — whether it lives at $PWD or several
# levels up because $PWD has none — must be dropped before the loader
# runs source_env, otherwise it's sourced twice (once by us, once by
# direnv).
#
# Pre-fix the walker only dropped the innermost when it equalled
# "$PWD/.envrc". That left the parent .envrc in the chain whenever $PWD
# itself had no .envrc — common when a parent directory carries shared
# config (e.g. ~/code/<scope>/.envrc) and the repo below it has no
# .envrc of its own.
@test "F-DROP: walker excludes nearest ancestor when PWD has no .envrc" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a/b"
    echo 'parent' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    # NB: no .envrc at /d/a/b — this is the bug-triggering shape.
    cd "$BATS_TEST_TMPDIR/d/a/b"
    DIRENV_RECURSIVE_DEPTH=3
    local out
    out=$(_direnv_recursive_walk)
    # direnv would natively load /d/a/.envrc as the active RC, so the
    # walker must not emit it. Output must be empty.
    [ -z "$out" ]
}

@test "F-DROP: walker excludes own .envrc when PWD has one (positive control)" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a"
    echo 'own' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    cd "$BATS_TEST_TMPDIR/d/a"
    DIRENV_RECURSIVE_DEPTH=3
    local out
    out=$(_direnv_recursive_walk)
    # direnv natively loads $PWD/.envrc; walker emits nothing.
    [ -z "$out" ]
}

@test "F-DROP: walker emits ancestors above the nearest, even when PWD has no .envrc" {
    mkdir -p "$BATS_TEST_TMPDIR/d/a/b/c"
    echo 'top' > "$BATS_TEST_TMPDIR/d/a/.envrc"
    echo 'mid' > "$BATS_TEST_TMPDIR/d/a/b/.envrc"
    # NB: no .envrc at /d/a/b/c — direnv natively loads b/.envrc.
    cd "$BATS_TEST_TMPDIR/d/a/b/c"
    DIRENV_RECURSIVE_DEPTH=3
    local out
    out=$(_direnv_recursive_walk)
    # b/.envrc is direnv's choice — drop it.
    # a/.envrc is the additional ancestor — emit it.
    [ "$(printf '%s\n' "$out" | grep -c '/.envrc$')" -eq 1 ]
    [[ "$out" == *"/d/a/.envrc"* ]]
    [[ "$out" != *"/d/a/b/.envrc"* ]]
}
