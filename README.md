# direnvrc-recursive

A direnv extension that loads every ancestor `.envrc` going up from `$PWD`, not just the nearest one.

## Why

direnv loads only the closest `.envrc` walking up from `$PWD`. If you keep shared config at `~/code/.envrc` and work in `~/code/foo/bar/`, the inner project doesn't see it. The documented workaround is `source_up` inside each child `.envrc`, but that means editing every project to opt in.

This loader walks the chain explicitly from `direnvrc` (sourced once per direnv evaluation) and loads each ancestor `.envrc` direnv would have allowed on its own. Children stay clean. The chain is hashed and gated by direnv's own allow database — no extra trust path.

The approach is from md2k's snippet on [direnv issue #190](https://github.com/direnv/direnv/issues/190#issuecomment-3286617153), reimplemented against direnv's Go source so the security check matches byte-for-byte.

## Install

```sh
git clone https://github.com/pragmatist-nz/direnvrc-recursive.git
cd direnvrc-recursive
just setup    # symlinks ./direnvrc into $XDG_CONFIG_HOME/direnv/direnvrc
```

Or symlink manually:

```sh
ln -s "$PWD/direnvrc" "${XDG_CONFIG_HOME:-$HOME/.config}/direnv/direnvrc"
```

This repo assumes direnv is already on `$PATH` and your shell hooks it (`eval "$(direnv hook bash)"` or the zsh equivalent). Installing direnv itself is out of scope.

## Activate

Off by default. Set `DIRENV_RECURSIVE_DEPTH` in your shell rc to opt in:

```sh
export DIRENV_RECURSIVE_DEPTH=3
```

The number bounds how many parent directories above `$PWD` get walked. `3` covers `~/code/<scope>/<repo>` with one level to spare. Unset, empty, or `0` means inert. Non-numeric values are treated as `0` (fail-closed, with a warning to stderr).

## Security

Each ancestor `.envrc` is authorized on its own merits. The loader mirrors direnv's `Allowed()` check from `internal/cmd/rc.go`:

1. deny database hit → never load
2. allow database hit (content-hash match) → load
3. `direnv.toml` `[whitelist].exact` match → load
4. `direnv.toml` `[whitelist].prefix` match → load
5. otherwise → skip (fail-closed)

Hashes match direnv's algorithm: `sha256(filepath.Abs(path) + "\n" + contents)`, stored at `$XDG_DATA_HOME/direnv/{allow,deny}/<hex_digest>`. The TOML whitelist is parsed by Python's `tomllib`, so configs direnv accepts are accepted here and configs direnv rejects are rejected here. Children that previously relied on `source_up` are not silently auto-trusted — they're checked the same as any other `.envrc`.

## First run

In a tree with pre-existing `.envrc` files, expect a wall of:

```
direnv: skipping ancestor: ~/code/.envrc (run: direnv allow ~/code)
```

The hint is the resolution. Run the printed command for each ancestor you trust.

## Quiet mode

Set `DIRENV_RECURSIVE_QUIET=1` to silence the per-file load/skip lines after onboarding. Operational warnings (parse errors, missing tools) print regardless.

## Compatibility

- bash 3.2+ (macOS system bash works; no bash-4 features used)
- `sha256sum` (GNU coreutils) or `shasum` (BSD/macOS) on `$PATH`
- Python 3.11+ on `$PATH` only if you use the `direnv.toml` whitelist
- CI runs on `ubuntu-latest` and `macos-latest`

## Develop

```sh
mise install     # bats, shellcheck, just
just test        # bats regression suite
just lint        # shellcheck
```

Tests source the loader as a library (`DIRENV_RECURSIVE_LIB_ONLY=1`) so individual functions can be exercised without triggering the auto-load. New regressions go in `test/loader.bats` with an `F<n>:` prefix that names the bug.

## License

MIT. See `LICENSE`.
