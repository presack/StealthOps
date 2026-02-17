"""FastAPI web application for StealthOps."""

from __future__ import annotations

import html
import json

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from core_ops import QueryConfig, StealthQueryEngine
from tor_engine import TorEngine


TAILWIND_CDN = "https://cdn.tailwindcss.com"


def build_app(
    tor_update_mode: str = "auto",
    tor_update_manifest: str | None = None,
    prefer_system_tor: bool = False,
) -> FastAPI:
    app = FastAPI(title="StealthOps")

    tor_engine = TorEngine(
        tor_update_mode=tor_update_mode,
        tor_update_manifest=tor_update_manifest,
        prefer_system_tor=prefer_system_tor,
    )
    tor_engine.ensure_tor()
    query_engine = StealthQueryEngine(tor_engine, QueryConfig(block_non_tor=False))

    def get_tor_ok() -> bool:
        if tor_engine.is_proxy_running():
            return tor_engine.verify_circuit()
        return False

    def render_kv_rows(data: dict) -> str:
        rows = []
        for key, value in data.items():
            if isinstance(value, list):
                value_str = ", ".join(str(v) for v in value) if value else "-"
            elif isinstance(value, dict):
                value_str = json.dumps(value, ensure_ascii=True)
            else:
                value_str = str(value) if value not in (None, "") else "-"
            rows.append(
                f"<tr><td class='py-1 pr-3 text-slate-400'>{html.escape(str(key))}</td>"
                f"<td class='py-1 text-slate-100'>{html.escape(value_str)}</td></tr>"
            )
        return "".join(rows)

    def render_results(results: dict, show_json: bool) -> str:
        dns_data = results.get("dns", {})
        mx_data = results.get("mx", {})
        whois_data = results.get("whois", {})
        header_data = results.get("headers", {})

        mx_rows = ""
        for item in mx_data.get("mx", []):
            prio = item.get("priority")
            host = item.get("host", "")
            mx_rows += (
                "<tr>"
                f"<td class='py-1 pr-3'>{html.escape(str(prio) if prio is not None else '-')}</td>"
                f"<td class='py-1'>{html.escape(str(host))}</td>"
                "</tr>"
            )
        if not mx_rows:
            mx_rows = "<tr><td class='py-1 pr-3' colspan='2'>No MX records</td></tr>"

        headers_rows = ""
        for key, value in header_data.get("headers", {}).items():
            headers_rows += (
                "<tr>"
                f"<td class='py-1 pr-3 text-slate-400'>{html.escape(str(key))}</td>"
                f"<td class='py-1 text-slate-100'>{html.escape(str(value))}</td>"
                "</tr>"
            )
        if not headers_rows:
            headers_rows = "<tr><td class='py-1 pr-3' colspan='2'>No headers</td></tr>"

        whois_summary = {
            key: whois_data.get(key)
            for key in [
                "domain_name",
                "registrar",
                "creation_date",
                "expiration_date",
                "name_servers",
                "status",
                "whois_error",
            ]
            if key in whois_data
        }

        json_panel = ""
        if show_json:
            json_panel = (
                "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>"
                "<h3 class='font-semibold mb-2'>Raw JSON</h3>"
                f"<pre class='bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-xs'>{html.escape(json.dumps(results, indent=2))}</pre>"
                "</section>"
            )

        return f"""
<section class='grid md:grid-cols-2 gap-4 mt-6'>
  <article class='bg-slate-800/70 rounded-xl p-4 shadow-xl'>
    <h3 class='font-semibold mb-2'>DNS</h3>
    <table class='text-sm w-full'><tbody>{render_kv_rows(dns_data)}</tbody></table>
  </article>
  <article class='bg-slate-800/70 rounded-xl p-4 shadow-xl'>
    <h3 class='font-semibold mb-2'>MX</h3>
    <table class='text-sm w-full'>
      <thead><tr><th class='text-left py-1 pr-3 text-slate-400'>Priority</th><th class='text-left py-1 text-slate-400'>Host</th></tr></thead>
      <tbody>{mx_rows}</tbody>
    </table>
  </article>
</section>
<section class='grid md:grid-cols-2 gap-4 mt-4'>
  <article class='bg-slate-800/70 rounded-xl p-4 shadow-xl'>
    <h3 class='font-semibold mb-2'>HTTP Headers</h3>
    <table class='text-sm w-full'>
      <thead><tr><th class='text-left py-1 pr-3 text-slate-400'>Header</th><th class='text-left py-1 text-slate-400'>Value</th></tr></thead>
      <tbody>{headers_rows}</tbody>
    </table>
  </article>
  <article class='bg-slate-800/70 rounded-xl p-4 shadow-xl'>
    <h3 class='font-semibold mb-2'>WHOIS (Key Fields)</h3>
    <table class='text-sm w-full'><tbody>{render_kv_rows(whois_summary)}</tbody></table>
  </article>
</section>
{json_panel}
"""

    def render_page(
        results: dict | None = None,
        target: str = "",
        block_non_tor: bool = False,
        route_mode: str = "stealth",
        show_json: bool = False,
        error: str = "",
        notice: str = "",
        manifest_url: str = "",
    ) -> str:
        current_tor_ok = get_tor_ok()
        shield_class = "bg-emerald-600" if current_tor_ok else "bg-red-600"
        shield_text = "TOR ROUTED" if current_tor_ok else "STANDARD ROUTE"
        warning = "" if current_tor_ok else f"<p class='text-red-400 text-sm mt-2'>Warning: {tor_engine.last_error or 'Tor unavailable'}.</p>"
        runtime_note = (
            f"<p class='text-slate-300 text-xs mt-2'>Runtime: {tor_engine.last_update_message}</p>"
            if tor_engine.last_update_message
            else ""
        )
        checked = "checked" if block_non_tor else ""
        show_json_checked = "checked" if show_json else ""
        notice_html = f"<p class='text-cyan-300 mt-3'>{notice}</p>" if notice else ""

        result_html = render_results(results, show_json) if results else ""

        error_html = f"<p class='text-red-400 mt-3'>{error}</p>" if error else ""
        stealth_active = "bg-cyan-600 text-white" if route_mode == "stealth" else "bg-slate-700 text-slate-200"
        public_active = "bg-orange-600 text-white" if route_mode == "public" else "bg-slate-700 text-slate-200"
        tor_manage = ""
        if not current_tor_ok:
            tor_manage = f"""
    <section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
      <h2 class='text-lg font-semibold'>Tor Setup</h2>
      <p class='text-sm text-slate-300 mt-1'>No verified Tor route detected. You can bootstrap or update managed Tor runtime now.</p>
      <form method='post' action='/tor/manage' class='mt-3 space-y-3'>
        <div>
          <label class='block text-sm mb-1'>Update Manifest URL (optional)</label>
          <input name='manifest_url' value='{html.escape(manifest_url)}' placeholder='https://host/tor-manifest.json' class='w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-sm' />
        </div>
        <button name='force_update' value='1' class='bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg font-semibold'>Install / Update Managed Tor</button>
      </form>
    </section>
"""

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
  <main class='max-w-6xl mx-auto p-6'>
    <header class='flex items-center justify-between mb-8'>
      <h1 class='text-3xl font-bold tracking-tight'>StealthOps</h1>
      <div class='px-4 py-2 rounded-full {shield_class} text-white text-sm font-semibold'>
        Privacy Shield: {shield_text}
      </div>
    </header>

    {warning}
    {runtime_note}

    <section class='bg-slate-800/70 rounded-xl p-5 shadow-xl'>
      <form method='post' action='/query' class='space-y-4'>
        <div>
          <label class='block text-sm mb-1'>Domain or URL</label>
          <input name='target' value='{html.escape(target)}' required class='w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2' />
        </div>
        <label class='flex items-center gap-2 text-sm'>
          <input type='checkbox' name='block_non_tor' {checked} />
          Block Non-Tor Traffic
        </label>
        <label class='flex items-center gap-2 text-sm'>
          <input type='checkbox' name='show_json' {show_json_checked} />
          Include Raw JSON Output
        </label>
        <div class='flex gap-3'>
          <button name='run_mode' value='stealth' class='px-4 py-2 rounded-lg font-semibold {stealth_active}'>Run Stealth Query (Tor)</button>
          <button name='run_mode' value='public' class='px-4 py-2 rounded-lg font-semibold {public_active}'>Run Fast Query (Public)</button>
        </div>
      </form>
      {error_html}
      {notice_html}
    </section>

    {tor_manage}

    <section class='mt-2'>
      {result_html}
    </section>
  </main>
</body>
</html>
"""

    @app.get("/", response_class=HTMLResponse)
    async def home() -> HTMLResponse:
        return HTMLResponse(render_page(route_mode="stealth", manifest_url=tor_engine.updater.manifest_url or ""))

    @app.post("/query", response_class=HTMLResponse)
    async def query(
        target: str = Form(...),
        block_non_tor: str | None = Form(None),
        run_mode: str = Form("stealth"),
        show_json: str | None = Form(None),
    ) -> HTMLResponse:
        query_engine.config.block_non_tor = bool(block_non_tor)
        query_engine.config.route_mode = "public" if run_mode == "public" else "stealth"
        try:
            results = query_engine.run_all(target.strip())
            notice = ""
            if query_engine.config.route_mode == "public":
                notice = "Public mode selected: requests are not routed through Tor."
            return HTMLResponse(
                render_page(
                    results=results,
                    target=target,
                    block_non_tor=bool(block_non_tor),
                    route_mode=query_engine.config.route_mode,
                    show_json=bool(show_json),
                    notice=notice,
                    manifest_url=tor_engine.updater.manifest_url or "",
                )
            )
        except Exception as exc:
            return HTMLResponse(
                render_page(
                    target=target,
                    block_non_tor=bool(block_non_tor),
                    route_mode=query_engine.config.route_mode,
                    show_json=bool(show_json),
                    error=str(exc),
                    manifest_url=tor_engine.updater.manifest_url or "",
                )
            )

    @app.post("/tor/manage", response_class=HTMLResponse)
    async def tor_manage(force_update: str | None = Form(None), manifest_url: str | None = Form(None)) -> HTMLResponse:
        if manifest_url and manifest_url.strip():
            tor_engine.updater.manifest_url = manifest_url.strip()
        message = tor_engine.manage_tor_runtime(force_update=bool(force_update))
        return HTMLResponse(
            render_page(
                route_mode="stealth",
                notice=message,
                manifest_url=tor_engine.updater.manifest_url or "",
            )
        )

    return app
