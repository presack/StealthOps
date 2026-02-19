"""FastAPI web application for StealthOps."""

from __future__ import annotations

import html
import ipaddress
import json
import threading
import time
import uuid

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse

from core_ops import QueryConfig, StealthQueryEngine, internet_available
from tor_engine import TorEngine


TAILWIND_CDN = "https://cdn.tailwindcss.com"


def human_label(key: str) -> str:
    labels = {
        "domain_name": "Domain Name",
        "creation_date": "Creation Date",
        "expiration_date": "Expiration Date",
        "updated_date": "Updated Date",
        "whois_server": "WHOIS Server",
        "name_servers": "Name Servers",
        "canonical_name": "Canonical Name",
        "derived_domain": "Derived Domain",
        "aliases": "Aliases",
        "addresses": "Addresses",
        "address_lookup_error": "Address Lookup Error",
        "registrar_iana_id": "Registrar IANA ID",
        "status": "Domain Status",
        "whois_error": "WHOIS Error",
        "network_whois_error": "Network WHOIS Error",
        "network_whois_warning": "Network WHOIS Warning",
        "asn": "ASN",
        "net_name": "Net Name",
        "net_handle": "Net Handle",
        "net_type": "Net Type",
        "parent_handle": "Parent Handle",
        "ip_version": "IP Version",
        "start_address": "Start Address",
        "end_address": "End Address",
        "rdap_url": "RDAP URL",
        "abuse_email": "Abuse Email",
        "abuse_phone": "Abuse Phone",
        "tor_routed": "Tor Routed",
        "status_code": "Status Code",
        "final_url": "Final URL",
    }
    if key in labels:
        return labels[key]
    return key.replace("_", " ").strip().title()


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
    query_engine = StealthQueryEngine(tor_engine, QueryConfig(block_non_tor=False, route_mode="public"))
    jobs_lock = threading.Lock()
    jobs: dict[str, dict] = {}

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
                f"<tr><td class='py-1 pr-3 align-top w-56 text-slate-400'>{html.escape(human_label(str(key)))}:</td>"
                f"<td class='py-1 pl-2 align-top text-slate-100 break-all'>{html.escape(value_str)}</td></tr>"
            )
        return "".join(rows)

    def render_record_lines(record_text: str) -> str:
        if not record_text.strip():
            return "<p class='text-slate-400 text-sm'>Awaiting data...</p>"
        rows = []
        for raw_line in record_text.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                rows.append("<tr><td class='py-1' colspan='2'>&nbsp;</td></tr>")
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                rows.append(
                    "<tr>"
                    f"<td class='py-1 pr-3 align-top w-56 text-slate-400'>{html.escape(key.strip())}:</td>"
                    f"<td class='py-1 pl-2 align-top text-slate-100 break-all'>{html.escape(value.strip())}</td>"
                    "</tr>"
                )
            else:
                rows.append(
                    "<tr>"
                    f"<td class='py-1 text-slate-100 break-words' colspan='2'>{html.escape(line)}</td>"
                    "</tr>"
                )
        return f"<table class='text-sm w-full'><tbody>{''.join(rows)}</tbody></table>"

    def render_pre_block(record_text: str, compact: bool = False) -> str:
        if not record_text.strip():
            return "<p class='text-slate-400 text-sm'>Awaiting data...</p>"
        leading = " leading-tight" if compact else ""
        return (
            "<pre class='text-sm whitespace-pre-wrap break-words text-slate-100"
            + leading
            + "'>"
            + html.escape(record_text)
            + "</pre>"
        )

    def render_results(results: dict, show_json: bool) -> str:
        address_data = results.get("address", {})
        dns_data = results.get("dns", {})
        mx_data = results.get("mx", {})
        whois_data = results.get("whois", {})
        network_whois_data = results.get("network_whois", {})
        header_data = results.get("headers", {})

        address_summary = {
            key: address_data.get(key)
            for key in [
                "query",
                "canonical_name",
                "derived_domain",
                "aliases",
                "addresses",
                "address_lookup_error",
            ]
            if key in address_data
        }
        def compact_notice(value: str, max_len: int = 120) -> str:
            text = str(value or "").strip()
            if not text:
                return ""
            line = text.splitlines()[0].strip()
            lower_line = line.lower()
            if "connection reset by peer" in lower_line:
                return "WHOIS server reset the connection."
            if line.lower().startswith("no a/aaaa record available for network whois"):
                return "No IP address available for network WHOIS lookup."
            if len(line) > max_len:
                return line[: max_len - 3].rstrip() + "..."
            return line

        whois_record = str(whois_data.get("domain_whois_record", "")).strip()
        whois_error = compact_notice(whois_data.get("whois_error", ""))
        whois_warning = compact_notice(whois_data.get("whois_warning", ""))
        network_whois_record = str(network_whois_data.get("network_whois_record", "")).strip()
        network_notice = compact_notice(
            network_whois_data.get("network_whois_warning")
            or network_whois_data.get("network_whois_error")
            or ""
        )
        query_value = str(address_data.get("query", "")).strip()
        is_ip_query = False
        try:
            ipaddress.ip_address(query_value)
            is_ip_query = True
        except Exception:
            is_ip_query = False

        address_error = compact_notice(address_data.get("address_lookup_error", ""))
        canonical_name = str(address_data.get("canonical_name", "")).strip()
        ip_reverse_lookup_failed = bool(
            is_ip_query and address_error and (not canonical_name or canonical_name == query_value)
        )

        dns_notices = []
        for key in sorted(k for k in dns_data.keys() if k.endswith("_error") and k != "ptr_error"):
            dns_notices.append(f"{key.replace('_', ' ').strip()}: {compact_notice(dns_data.get(key, ''))}")
        ptr_error = compact_notice(dns_data.get("ptr_error", ""))
        if ptr_error:
            if is_ip_query and "." in query_value:
                ptr_name = ".".join(reversed(query_value.split("."))) + ".in-addr.arpa"
                ptr_kind = "NameError" if "does not exist" in ptr_error.lower() or "nxdomain" in ptr_error.lower() else ptr_error
                dns_notices.append(f"DNS query for {ptr_name} returned an error from the server: {ptr_kind}")
            else:
                dns_notices.append(f"ptr error: {ptr_error}")
        if mx_data.get("mx_error"):
            dns_notices.append(f"mx error: {compact_notice(mx_data.get('mx_error', ''))}")

        def format_soa_data(value: str) -> str:
            parts = str(value).split()
            if len(parts) < 7:
                return str(value)
            mname, rname, serial, refresh, retry, expire, minimum = parts[:7]
            return (
                f"mname={mname}; rname={rname}; serial={serial}; "
                f"refresh={refresh}; retry={retry}; expire={expire}; minimum={minimum}"
            )

        dns_rows = []
        domain = str(dns_data.get("domain", "-"))
        for rtype, key in (
            ("A", "a"),
            ("AAAA", "aaaa"),
            ("PTR", "ptr"),
            ("NS", "ns"),
            ("TXT", "txt"),
            ("CNAME", "cname"),
            ("CAA", "caa"),
            ("SOA", "soa"),
        ):
            values = dns_data.get(key, [])
            for value in values:
                data_value = format_soa_data(str(value)) if rtype == "SOA" else str(value)
                dns_rows.append(
                    "<tr>"
                    f"<td class='py-1 pr-3 align-top whitespace-nowrap'>{html.escape(domain)}</td>"
                    "<td class='py-1 pr-3 align-top whitespace-nowrap'>IN</td>"
                    f"<td class='py-1 pr-3 align-top whitespace-nowrap'>{rtype}</td>"
                    f"<td class='py-1 align-top break-all'>{html.escape(data_value)}</td>"
                    "<td class='py-1 pl-3 align-top text-slate-400 whitespace-nowrap'>-</td>"
                    "</tr>"
                )
        for mx in mx_data.get("mx", []):
            priority = mx.get("priority")
            host = mx.get("host", "-")
            data_value = f"preference={priority}; exchange={host}" if priority is not None else f"exchange={host}"
            dns_rows.append(
                "<tr>"
                f"<td class='py-1 pr-3 align-top whitespace-nowrap'>{html.escape(domain)}</td>"
                "<td class='py-1 pr-3 align-top whitespace-nowrap'>IN</td>"
                "<td class='py-1 pr-3 align-top whitespace-nowrap'>MX</td>"
                f"<td class='py-1 align-top break-all'>{html.escape(data_value)}</td>"
                "<td class='py-1 pl-3 align-top text-slate-400 whitespace-nowrap'>-</td>"
                "</tr>"
            )
        dns_records_html = "".join(dns_rows) if dns_rows else "<tr><td class='py-1 pr-3' colspan='5'>No records to display</td></tr>"

        headers_rows = ""
        for key, value in header_data.get("headers", {}).items():
            headers_rows += (
                "<tr>"
                f"<td class='py-1 pr-3 text-slate-400'>{html.escape(str(key))}</td>"
                f"<td class='py-1 text-slate-100 break-all'>{html.escape(str(value))}</td>"
                "</tr>"
            )
        if not headers_rows:
            headers_rows = "<tr><td class='py-1 pr-3' colspan='2'>No headers</td></tr>"

        json_panel = ""
        if show_json:
            json_panel = (
                "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>"
                "<h3 class='font-semibold mb-2'>Raw JSON</h3>"
                f"<pre class='bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-xs'>{html.escape(json.dumps(results, indent=2))}</pre>"
                "</section>"
            )

        whois_cmd = html.escape(f"whois {dns_data.get('domain', '<domain>')}")
        http_cmd = html.escape(f"curl -I {header_data.get('url', '<url>')}")
        whois_missing_domain = (
            is_ip_query
            and whois_error.lower().startswith("unable to derive domain for whois from ip target")
            and not whois_record
        )

        if ip_reverse_lookup_failed:
            address_panel_html = (
                "<p class='text-slate-100 text-sm'><span class='text-amber-300'>lookup failed</span> "
                + html.escape(query_value)
                + "</p>"
                "<p class='text-slate-300 text-sm mt-1'>Could not find a domain name corresponding to this IP address.</p>"
            )
        elif address_summary:
            address_panel_html = f"<table class='text-sm w-full'><tbody>{render_kv_rows(address_summary)}</tbody></table>"
        else:
            address_panel_html = "<p class='text-slate-400 text-sm'>Awaiting data...</p>"

        if whois_missing_domain:
            whois_panel_html = "<p class='text-slate-300 text-sm'>Don't have a domain name for which to get a record</p>"
        elif whois_record:
            whois_panel_html = render_pre_block(whois_record, compact=True)
        elif whois_error:
            whois_panel_html = "<p class='text-slate-300 text-sm'>No WHOIS record returned.</p>"
        elif whois_warning:
            whois_panel_html = "<p class='text-slate-300 text-sm'>Attempting WHOIS lookup...</p>"
        else:
            whois_panel_html = "<p class='text-slate-400 text-sm'>Awaiting data...</p>"

        if network_whois_record:
            network_panel_html = render_record_lines(network_whois_record)
            network_panel_min_h = "min-h-[12rem]"
        elif network_notice:
            network_panel_html = "<p class='text-slate-300 text-sm'>No network WHOIS record to display.</p>"
            network_panel_min_h = "min-h-[4rem]"
        else:
            network_panel_html = "<p class='text-slate-400 text-sm'>Awaiting data...</p>"
            network_panel_min_h = "min-h-[12rem]"

        return f"""
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-6'>
  <h3 class='font-semibold mb-2'>Address lookup</h3>
  <div class='min-h-[4rem]'>
    {address_panel_html}
  </div>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2' title='{whois_cmd}'>Domain Whois summary</h3>
  <div class='min-h-[4rem]'>
    {("<p class='text-amber-300 text-xs mb-2 break-words'>" + html.escape(whois_warning) + "</p>") if whois_warning else ""}
    {("<p class='text-amber-300 text-xs mb-2 break-words'>" + html.escape(whois_error) + "</p>") if whois_error and not whois_missing_domain else ""}
    {whois_panel_html}
  </div>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2'>Network Whois record</h3>
  {"<p class='text-amber-300 text-xs mb-2'>" + html.escape(network_notice) + "</p>" if network_notice else ""}
  <div class='{network_panel_min_h}'>
    {network_panel_html}
  </div>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2'>DNS records</h3>
  {"".join("<p class='text-amber-300 text-xs mb-2 break-words'>" + html.escape(note) + "</p>" for note in dns_notices)}
  <table class='text-sm w-full table-auto'>
    <thead><tr><th class='text-left py-1 pr-3 text-slate-400'>Name</th><th class='text-left py-1 pr-3 text-slate-400'>Class</th><th class='text-left py-1 pr-3 text-slate-400'>Type</th><th class='text-left py-1 text-slate-400'>Data</th><th class='text-left py-1 pl-3 text-slate-400'>TTL</th></tr></thead>
    <tbody>{dns_records_html}</tbody>
  </table>
</section>
<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
  <h3 class='font-semibold mb-2' title='{http_cmd}'>HTTP Headers</h3>
  <table class='text-sm w-full'>
    <tbody>
      <tr><td class='py-1 pr-3 text-slate-400'>URL</td><td class='py-1 break-all'>{html.escape(str(header_data.get('url', '-')))}</td></tr>
      <tr><td class='py-1 pr-3 text-slate-400'>Status Code</td><td class='py-1'>{html.escape(str(header_data.get('status_code', '-')))}</td></tr>
      <tr><td class='py-1 pr-3 text-slate-400'>Final URL</td><td class='py-1 break-all'>{html.escape(str(header_data.get('final_url', '-')))}</td></tr>
      <tr><td class='py-1 pr-3 text-slate-400'>Tor Routed</td><td class='py-1'>{html.escape(str(header_data.get('tor_routed', '-')))}</td></tr>
    </tbody>
  </table>
  <table class='text-sm w-full mt-3'>
    <thead><tr><th class='text-left py-1 pr-3 text-slate-400'>Header</th><th class='text-left py-1 text-slate-400'>Value</th></tr></thead>
    <tbody>{headers_rows}</tbody>
  </table>
</section>
{json_panel}
"""

    def render_page(
        results: dict | None = None,
        target: str = "",
        route_mode: str = "public",
        error: str = "",
        notice: str = "",
        update_source: str = "",
    ) -> str:
        stealth_ready = get_tor_ok()
        shield_class = "bg-cyan-600" if route_mode == "public" else ("bg-emerald-600" if stealth_ready else "bg-red-600")
        shield_text = "PUBLIC MODE" if route_mode == "public" else ("STEALTH MODE READY" if stealth_ready else "STEALTH MODE UNAVAILABLE")
        warning = ""
        if route_mode == "stealth" and not stealth_ready:
            warning = f"<p class='text-red-400 text-sm mt-2'>Warning: {tor_engine.last_error or 'Tor unavailable'}.</p>"
        runtime_note = (
            f"<p class='text-slate-300 text-xs mt-2'>Runtime: {tor_engine.last_update_message}</p>"
            if tor_engine.last_update_message
            else ""
        )
        notice_html = f"<p class='text-cyan-300 mt-3'>{notice}</p>" if notice else ""

        result_html = render_results(results, False) if results else ""

        error_html = f"<p class='text-red-400 mt-3'>{error}</p>" if error else ""
        stealth_active = "bg-emerald-600 text-white" if route_mode == "stealth" else "bg-slate-700 text-slate-200"
        public_active = "bg-cyan-600 text-white" if route_mode == "public" else "bg-slate-700 text-slate-200"
        switch_to = "stealth" if route_mode == "public" else "public"
        switch_label = "Switch to Stealth Mode" if route_mode == "public" else "Switch to Public Mode"
        tor_manage = ""
        if route_mode == "stealth" and not stealth_ready:
            tor_manage = f"""
    <section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'>
      <h2 class='text-lg font-semibold'>Tor Setup</h2>
      <p class='text-sm text-slate-300 mt-1'>No verified Tor route detected for Stealth Mode. You can bootstrap or update managed Tor runtime now.</p>
      <p class='text-xs text-slate-400 mt-1'>Download can take 1-2 minutes depending on connection speed.</p>
      <p class='text-xs text-slate-400 mt-2 break-all'>{html.escape(update_source)}</p>
      <form method='post' action='/tor/manage' class='mt-3 space-y-3' onsubmit="const btn=this.querySelector('button[type=submit]'); if (btn) {{ btn.disabled=true; btn.textContent='Downloading Tor...'; btn.classList.add('opacity-70','cursor-not-allowed'); }}">
        <label class='flex items-center gap-2 text-sm'>
          <input type='checkbox' name='confirm_download' />
          Confirm download from the source above
        </label>
        <button type='submit' name='force_update' value='1' class='bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg font-semibold'>Install / Update Managed Tor</button>
      </form>
    </section>
"""
        run_button_label = "Run Query (Stealth)" if route_mode == "stealth" else "Run Query (Public)"
        run_button_class = "bg-emerald-600 hover:bg-emerald-500" if route_mode == "stealth" else "bg-cyan-600 hover:bg-cyan-500"

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
      <div>
        <h1 class='text-3xl font-bold tracking-tight'>StealthOps</h1>
        <p class='text-slate-400 text-xs mt-1'>Privacy-centric network intelligence</p>
      </div>
      <div class='flex items-center gap-3'>
        <div class='px-4 py-2 rounded-full {shield_class} text-white text-sm font-semibold'>
          Privacy Shield: {shield_text}
        </div>
        <form method='post' action='/mode'>
          <input type='hidden' name='route_mode' value='{html.escape(switch_to)}' />
          <button class='text-sm underline text-slate-300 hover:text-white'>{html.escape(switch_label)}</button>
        </form>
      </div>
    </header>

    {warning}
    {runtime_note}

    <section class='bg-slate-800/70 rounded-xl p-5 shadow-xl'>
      <form id='query-form' method='post' action='/query' class='space-y-4'>
        <div>
          <label class='block text-sm mb-1'>Domain or URL</label>
          <input name='target' value='{html.escape(target)}' required class='w-full rounded-lg bg-slate-900 border border-slate-700 px-3 py-2' />
        </div>
        <input type='hidden' name='route_mode' value='{html.escape(route_mode)}' />
        <div class='flex gap-3'>
          <button class='px-4 py-2 rounded-lg font-semibold text-white {run_button_class}'>{html.escape(run_button_label)}</button>
          <span class='self-center text-xs text-slate-400'>{"Tor-routed where available." if route_mode == "stealth" else "Fast public route."}</span>
        </div>
      </form>
      {error_html}
      {notice_html}
    </section>

    {tor_manage}

    <section class='mt-2'>
      <div id='results-panel'>{result_html}</div>
    </section>
  </main>
  <script>
    (function() {{
      const form = document.getElementById('query-form');
      const panel = document.getElementById('results-panel');
      if (!form || !panel) return;

      async function pollJob(jobId) {{
        while (true) {{
          const res = await fetch(`/query/status/${{jobId}}`);
          if (!res.ok) {{
            panel.innerHTML = "<p class='text-red-400'>Failed to load query status.</p>";
            return;
          }}
          const data = await res.json();
          if (typeof data.html === 'string') {{
            panel.innerHTML = data.html;
          }}
          if (data.done) {{
            return;
          }}
          await new Promise(r => setTimeout(r, 400));
        }}
      }}

      form.addEventListener('submit', async function(ev) {{
        ev.preventDefault();
        panel.innerHTML = ""
          + "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-6'><h3 class='font-semibold mb-2'>Address lookup</h3><div class='min-h-[9rem] text-slate-400 text-sm'>Collecting...</div></section>"
          + "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'><h3 class='font-semibold mb-2'>Domain Whois summary</h3><div class='min-h-[18rem] text-slate-400 text-sm'>Collecting...</div></section>"
          + "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'><h3 class='font-semibold mb-2'>Network Whois record</h3><div class='min-h-[12rem] text-slate-400 text-sm'>Collecting...</div></section>";
        const body = new FormData(form);
        const res = await fetch('/query/start', {{ method: 'POST', body }});
        if (!res.ok) {{
          let msg = "Failed to start query.";
          try {{
            const errData = await res.json();
            if (errData && errData.error) msg = errData.error;
          }} catch (_) {{}}
          panel.innerHTML = "<p class='text-red-400'>" + msg + "</p>";
          return;
        }}
        const data = await res.json();
        if (!data.job_id) {{
          panel.innerHTML = "<p class='text-red-400'>Query did not return a job id.</p>";
          return;
        }}
        pollJob(data.job_id);
      }});
    }})();
  </script>
</body>
</html>
"""

    @app.get("/", response_class=HTMLResponse)
    async def home() -> HTMLResponse:
        return HTMLResponse(
            render_page(
                route_mode=query_engine.config.route_mode,
                update_source=tor_engine.preview_update_source(),
            )
        )

    @app.post("/mode", response_class=HTMLResponse)
    async def set_mode(route_mode: str = Form("public")) -> HTMLResponse:
        selected = "stealth" if route_mode == "stealth" else "public"
        query_engine.config.route_mode = selected
        notice = f"Routing mode set to {selected}."
        if selected == "stealth":
            tor_ok = tor_engine.ensure_tor()
            if tor_ok:
                notice = "Routing mode set to stealth. Tor route verified."
            else:
                notice = f"Routing mode set to stealth, but Tor is unavailable: {tor_engine.last_error or 'unknown error'}"
        return HTMLResponse(
            render_page(
                route_mode=selected,
                notice=notice,
                update_source=tor_engine.preview_update_source(),
            )
        )

    @app.post("/query", response_class=HTMLResponse)
    async def query(
        target: str = Form(...),
        route_mode: str = Form("public"),
    ) -> HTMLResponse:
        query_engine.config.route_mode = "stealth" if route_mode == "stealth" else "public"
        query_engine.config.block_non_tor = query_engine.config.route_mode == "stealth"
        if query_engine.config.route_mode == "stealth":
            tor_engine.ensure_tor()
        try:
            results = query_engine.run_all(target.strip())
            notice = ""
            if query_engine.config.route_mode == "stealth" and not tor_engine.verify_circuit():
                notice = f"Stealth mode selected, but Tor is not verified: {tor_engine.last_error or 'unknown error'}"
            return HTMLResponse(
                render_page(
                    results=results,
                    target=target,
                    route_mode=query_engine.config.route_mode,
                    notice=notice,
                    update_source=tor_engine.preview_update_source(),
                )
            )
        except Exception as exc:
            return HTMLResponse(
                render_page(
                    target=target,
                    route_mode=query_engine.config.route_mode,
                    error=str(exc),
                    update_source=tor_engine.preview_update_source(),
                )
            )

    @app.post("/query/start", response_class=JSONResponse)
    async def query_start(
        target: str = Form(...),
        route_mode: str = Form("public"),
    ) -> JSONResponse:
        if not internet_available(timeout=1.0):
            return JSONResponse(
                {
                    "error": "internet connectivity check failed (no network route detected)",
                    "job_id": "",
                },
                status_code=503,
            )
        selected_mode = "stealth" if route_mode == "stealth" else "public"
        target_value = target.strip()
        job_id = uuid.uuid4().hex

        with jobs_lock:
            jobs[job_id] = {
                "done": False,
                "error": "",
                "results": {},
                "target": target_value,
                "route_mode": selected_mode,
                "updated_at": time.time(),
            }

        def worker() -> None:
            local_engine = StealthQueryEngine(
                tor_engine,
                QueryConfig(
                    block_non_tor=selected_mode == "stealth",
                    route_mode=selected_mode,
                ),
            )
            if selected_mode == "stealth":
                tor_engine.ensure_tor()

            def on_update(snapshot: dict) -> None:
                with jobs_lock:
                    if job_id not in jobs:
                        return
                    jobs[job_id]["results"] = snapshot
                    jobs[job_id]["updated_at"] = time.time()

            try:
                final = local_engine.run_all_staged(target_value, on_update=on_update)
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["results"] = final
                        jobs[job_id]["done"] = True
                        jobs[job_id]["updated_at"] = time.time()
            except Exception as exc:
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["error"] = str(exc)
                        jobs[job_id]["done"] = True
                        jobs[job_id]["updated_at"] = time.time()

        threading.Thread(target=worker, daemon=True).start()
        return JSONResponse({"job_id": job_id})

    @app.get("/query/status/{job_id}", response_class=JSONResponse)
    async def query_status(job_id: str) -> JSONResponse:
        with jobs_lock:
            job = jobs.get(job_id)
            if not job:
                return JSONResponse({"done": True, "error": "job not found", "html": "<p class='text-red-400'>Query job not found.</p>"}, status_code=404)
            results = job.get("results", {})
            done = bool(job.get("done"))
            error = str(job.get("error") or "")

        html_fragment = ""
        if error:
            html_fragment = f"<p class='text-red-400'>{html.escape(error)}</p>"
        elif results:
            html_fragment = render_results(results, False)
        else:
            html_fragment = "<section class='bg-slate-800/70 rounded-xl p-5 shadow-xl mt-4'><p class='text-slate-300'>Collecting results...</p></section>"

        return JSONResponse({"done": done, "error": error, "html": html_fragment})

    @app.post("/tor/manage", response_class=HTMLResponse)
    async def tor_manage(
        force_update: str | None = Form(None),
        confirm_download: str | None = Form(None),
    ) -> HTMLResponse:
        if not confirm_download:
            message = "Confirm download checked was not selected. Review source and confirm to proceed."
        else:
            message = tor_engine.manage_tor_runtime(force_update=bool(force_update))
        return HTMLResponse(
            render_page(
                route_mode="stealth",
                notice=message,
                update_source=tor_engine.preview_update_source(),
            )
        )

    return app
