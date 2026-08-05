"""Local dev server: `uv run python -m tbx.web`."""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("tbx.web.app:app", host="127.0.0.1", port=8765, reload=True)
