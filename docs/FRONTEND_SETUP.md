# React dashboard setup

The frontend is a React single-page application built with Vite. During development, Vite listens on `127.0.0.1:5173` and proxies `/api/*` requests to the Flask backend at `127.0.0.1:5000`.

## Requirements

- Node.js 18 or newer (Node 20 LTS or 22 LTS recommended)
- npm (included with Node.js)
- Flask backend dependencies installed in the project virtual environment

## Start both services

Terminal 1, from the project root:

```bash
source .venv/bin/activate
python -m security_analyzer.web
```

Terminal 2, from the project root:

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## Build frontend assets

```bash
cd frontend
npm install
npm run build
```

The build is written to `frontend/dist`. After building, start Flask from the project root. Flask serves `frontend/dist/index.html` at `/` and static assets under `/assets/`.

## Notes

- Keep the Flask server bound to localhost for this student project.
- The Vite proxy avoids a separate CORS configuration during local development.
- The browser submits a multipart `.py` file, `.zip` archive, or JSON source text to `POST /api/scan`.
- ZIP uploads are read in memory and are never extracted to disk.
- The New Analysis page has separate Bandit and mypy toggles. mypy diagnostics appear in a separate Type Safety panel.
- React masks likely secrets before showing source context and renders source-derived values as text.
- Source code is not saved to SQLite by the backend.


## v0.7.0 Security Assistant

When a scan is open, a floating assistant prompt appears at the bottom-right. Clicking the suggestion bubble requests a current-scan summary; clicking the chat icon opens the conversation panel. Each NVIDIA request asks for consent. The chat accepts only focused Python/security questions and short follow-ups. It rejects unrelated prompts, pasted source code, likely secrets, prompt-injection patterns, and explicit malware-building requests before calling the provider.

The backend sends a compact masked summary of the current scan and the user's short question. It never sends the original source file, file paths, or raw finding evidence to the chat endpoint. Chat history is kept in browser memory only. Without `NVIDIA_API_KEY`, the assistant uses deterministic local guidance and makes no external request.
