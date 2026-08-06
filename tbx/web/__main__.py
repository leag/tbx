"""Local dev server: `uv run python -m tbx.web`."""

import uvicorn

if __name__ == "__main__":
    # reload=True previously spawned its worker via multiprocessing's
    # "spawn" start method, which re-execs Python with a bootstrap command
    # line that no longer contains "tbx.web" -- a `pkill`/`ps`-pattern kill
    # on the expected command line then misses the actual listening worker,
    # leaving an orphaned process silently serving stale code on restart.
    # Not worth chasing for a tool that's restarted by hand after each
    # rebuild anyway.
    uvicorn.run("tbx.web.app:app", host="127.0.0.1", port=8765, reload=False)
