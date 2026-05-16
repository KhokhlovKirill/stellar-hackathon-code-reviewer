# Aegis Frontend

React + Vite + TypeScript + Tailwind CSS. The legacy Jinja templates remain in
`frontend/templates/` for backend compatibility, but the production application UI
is the React SPA in `frontend/src/`.

## Run

```bash
make docker-up
```

React UI: http://localhost:8099
Backend API: http://localhost:8080

For local frontend development:

```bash
cd frontend
npm install
npm run dev
```

Vite serves http://localhost:5173 and proxies API routes through the configured
`VITE_API_PROXY` target. Default: `http://localhost:8099`.
