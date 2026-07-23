# End-to-end tests

The end-to-end suite requires Docker with the Compose plugin. Run it from the
repository root:

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```

The script builds the `examples/build` stack, runs each phase in order, prints
container logs on failure, and cleans up.

Pass a phase's two-digit prefix to run only that phase:

```sh
FILTER_MODE=dns scripts/e2e.sh 09
FILTER_MODE=dns scripts/e2e.sh 09 13
```

Some phases recreate the stack. For those, `E2E_SKIP_INITIAL_UP=1` skips the
unused baseline startup. Check the phase script before using this option.

The dashboard phase can also run a browser smoke test:

```sh
cd dashboard/ui
pnpm install --frozen-lockfile
pnpm exec playwright install --with-deps chromium
cd ../..
FILTER_MODE=https E2E_BROWSER=1 scripts/e2e.sh 14
```

Phase scripts live in this directory and are named for the behavior they test.
They share helpers in `lib.sh`. Run local phases one at a time because they use
fixed container names and ports.

Resource limits can be adjusted with `E2E_MAX_MEMORY_MIB`,
`E2E_MAX_MEMORY_GROWTH_MIB`, `E2E_MAX_IDLE_CPU_PERCENT`, and
`E2E_CPU_SAMPLE_SECONDS`.
