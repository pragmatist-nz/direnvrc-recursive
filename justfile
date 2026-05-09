# Recipes for installing, testing, and linting the recursive direnvrc.
# `setup` symlinks ./direnvrc into $XDG_CONFIG_HOME/direnv/. Idempotent.
# Assumes the direnv binary is already on PATH and your shell hooks it
# (`eval "$(direnv hook bash|zsh)"`) — neither is installed by this repo.

set tempdir := "/tmp"
set fallback := true

# Symlink the recursive direnvrc into $XDG_CONFIG_HOME/direnv/. Idempotent.
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg="${XDG_CONFIG_HOME:-$HOME/.config}/direnv"
    mkdir -p "$cfg"
    ln -svfn "{{ source_directory() }}/direnvrc" "$cfg/direnvrc"

# Run the loader's bats regression suite.
test:
    bats {{ source_directory() }}/test

# Lint the loader with shellcheck.
lint:
    shellcheck --shell=bash {{ source_directory() }}/direnvrc
