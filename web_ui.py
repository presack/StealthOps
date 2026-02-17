"""FastAPI web application for StealthOps."""

from __future__ import annotations

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse

from core_ops import QueryConfig, StealthQueryEngine
from tor_engine import TorEngine


TAILWIND_CDN = "https://cdn.tailwindcss.com"


def build_app() -> FastAPI:
    app = FastAPI(title="StealthOps")

    tor_engine = TorEngine()
    tor_ok = tor_engine.ensure_tor()
    query_engine = StealthQueryEngine(tor_engine, QueryConfig(block_non_tor=False))

    def render_page(
        results: dict | None = None,
        target: str = "",
        block_non_tor: bool = False,
        error: str = "",
    ) -> str:
        shield_class = "bg-emerald-600" if tor_ok else "bg-red-600"
        shield_text = "TOR ROUTED" if tor_ok else "STANDARD ROUTE"
        warning = "" if tor_ok else f"<p class='text-red-400 text-sm mt-2'>Warning: {tor_engine.last_error or 'Tor unavailable'}.</p>"
        checked = "checked" if block_non_tor else ""

        result_html = ""
        if results:
            import json

            result_html = f"<pre class='bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-xs'>{json.dumps(results, indent=2)}</pre>"

        error_html = f"<p class='text-red-400 mt-3'>{error}</p>" if error else ""

        return f"""
<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>StealthOps</title>
  <script src='{TAILWIND_CDN}'></script>
</head>
<body class='bg-slate-950 text-slate-100 min-h-screen'>
  <main class='max-w-5xl mx-auto p-6'>
    <header class='flex items-center justify-between mb-8'>
      <h1 class='text-3xl font-bold tracking-tight'>StealthOps</h1>
      <div class='px-4 py-2 rounded-full {shield_class} text-white text-sm font-semibold'>
        ?? {shield_text}
      </div>
    </header>

    {warning}

    <section class='bg-slate-800/70 rounded-xl p-5 shadow-xl'>
      <form method='post' action='/query' class='space-y-4'>
        <div>
          <label class='block text-sm mb-1'>Domain or URL</label>
          <input name='target' value='{target}' required class='w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2' />
        </div>
        <label class='flex items-center gap-2 text-sm'>
          <input type='checkbox' name='block_non_tor' {checked} />
          Block Non-Tor Traffic
        </label>
        <button class='bg-cyan-600 hover:bg-cyan-500 px-4 py-2 rounded-lg font-semibold'>Run Stealth Query</button>
      </form>
      {error_html}
    </section>

    <section class='mt-6'>
      {result_html}
    </section>
  </main>
</body>
</html>
"""

    @app.get("/", response_class=HTMLResponse)
    async def home() -> HTMLResponse:
        return HTMLResponse(render_page())

    @app.post("/query", response_class=HTMLResponse)
    async def query(target: str = Form(...), block_non_tor: str | None = Form(None)) -> HTMLResponse:
        query_engine.config.block_non_tor = bool(block_non_tor)
        try:
            results = query_engine.run_all(target.strip())
            return HTMLResponse(render_page(results=results, target=target, block_non_tor=bool(block_non_tor)))
        except Exception as exc:
            return HTMLResponse(render_page(target=target, block_non_tor=bool(block_non_tor), error=str(exc)))

    return app
