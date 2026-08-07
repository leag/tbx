# tbx web UI frontend

React + Vite frontend for the tbx web UI: upload a Turbo Basic EXE, view the
decompiled source and IR, edit the source, and recompile it through the
oracle to check for a byte-exact match.

## Development

```sh
npm install
npm run dev
```

`npm run dev` starts the Vite dev server with a proxy to the FastAPI backend
(`tbx.web.app`, run separately).

## Production build

```sh
npm run build
```

This produces static assets in `dist/`, which `tbx.web.app` serves directly
when present.
