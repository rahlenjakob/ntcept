# README assets

These are generated from **real** ntcept output, not mocked up.

## Terminal cards (`*.svg`)

`flows.svg`, `postgres.svg`, `error.svg`, `modify.svg` are rendered by `terminal-cards.py`, which
turns lines of captured CLI output into a styled terminal panel. The text in each is verbatim from
a real `ntcept` run against `examples/nextjs`. To regenerate:

```bash
python3 assets/terminal-cards.py     # run from the repo root; writes assets/*.svg
```

## Inspector screenshots (`inspector.png`)

Captured from the live inspector (`ntcept ui`) with headless Chrome — no extension needed:

```bash
# with a session running (e.g. `ntcept run --keep -- npm run dev` in examples/nextjs)
PORT=$(ntcept status --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["session"]["control_port"])')
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --hide-scrollbars --force-device-scale-factor=2 --window-size=1360,560 \
  --screenshot=assets/inspector.png "http://127.0.0.1:$PORT/#flow=4"
```

The `#flow=<id>` fragment pre-selects a flow, so the detail pane is populated in the shot.
