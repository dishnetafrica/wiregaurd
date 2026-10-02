#!/usr/bin/env python3
"""Builds the customer manual (HTML + PDF) from one Markdown source.

Inputs : docs/manual/customer-setup-guide.md, docs/manual/config.json,
         windows/src/DishNet.SecureConnect.Core/Onboarding/help-topics.md (the in-app help, appended as an appendix)
Outputs: docs/manual/customer-setup-guide.html, docs/manual/customer-setup-guide.pdf,
         server/internal/api/manual/guide.html + guide.pdf (embedded in dishnet-vpnd, served at /guide and /guide.pdf)

PDF needs a Chromium binary (headless). Set CHROMIUM=/path/to/chrome or let the script find one.
"""
import glob, html, json, os, pathlib, re, shutil, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
cfg = json.loads((ROOT / "docs/manual/config.json").read_text())
md_src = (ROOT / "docs/manual/customer-setup-guide.md").read_text()
help_md = (ROOT / "windows/src/DishNet.SecureConnect.Core/Onboarding/help-topics.md").read_text()

# Appendix: in-app help topics, headings demoted one level, title line dropped.
help_body = "\n".join(l for l in help_md.splitlines() if not l.startswith("# "))
help_body = re.sub(r"^## ", "### ", help_body, flags=re.M)

DIAGRAM = """<figure class="diagram" aria-label="Diagram: office computer with Tally, encrypted DishNet connection, remote laptop showing the office desktop">
<svg viewBox="0 0 660 230" width="100%" role="img">
  <rect x="40" y="40" width="160" height="110" rx="8" fill="#fff" stroke="#1f2328" stroke-width="2"/>
  <rect x="100" y="152" width="40" height="14" fill="#1f2328"/><rect x="80" y="166" width="80" height="5" fill="#1f2328"/>
  <rect x="58" y="56" width="124" height="78" rx="4" fill="#f7f7f8"/>
  <text x="120" y="92" text-anchor="middle" font-size="20" font-weight="700" fill="#1f2328">Tally</text>
  <text x="120" y="112" text-anchor="middle" font-size="11" fill="#6b7280">company data</text>
  <text x="120" y="196" text-anchor="middle" font-size="12.5" font-weight="600" fill="#1f2328">Office computer</text>
  <text x="120" y="212" text-anchor="middle" font-size="11" fill="#6b7280">stays on · data stays here</text>
  <line x1="210" y1="95" x2="450" y2="95" stroke="#fde2e3" stroke-width="26" stroke-linecap="round"/>
  <line x1="214" y1="95" x2="446" y2="95" stroke="{red}" stroke-width="4" stroke-dasharray="6 6" stroke-linecap="round"/>
  <rect x="320" y="64" width="24" height="18" rx="3" fill="{red}"/><path d="M324,64 V60 A8,8 0 0 1 340,60 V64" stroke="{red}" stroke-width="3" fill="none"/>
  <text x="330" y="128" text-anchor="middle" font-size="12.5" font-weight="600" fill="#1f2328">Encrypted DishNet connection</text>
  <text x="330" y="144" text-anchor="middle" font-size="11" fill="#6b7280">only your authorised devices · nothing is copied</text>
  <rect x="470" y="48" width="160" height="100" rx="6" fill="#fff" stroke="#1f2328" stroke-width="2"/>
  <rect x="455" y="150" width="190" height="10" rx="3" fill="#1f2328"/>
  <rect x="482" y="60" width="136" height="76" rx="3" fill="#f7f7f8"/>
  <text x="550" y="82" text-anchor="middle" font-size="10" fill="#6b7280">Office desktop</text>
  <text x="550" y="104" text-anchor="middle" font-size="16" font-weight="700" fill="#1f2328">Tally</text>
  <text x="550" y="120" text-anchor="middle" font-size="9" fill="#6b7280">via Remote Desktop</text>
  <text x="550" y="196" text-anchor="middle" font-size="12.5" font-weight="600" fill="#1f2328">Your laptop, anywhere</text>
  <text x="550" y="212" text-anchor="middle" font-size="11" fill="#6b7280">sees and controls the office screen</text>
</svg>
<figcaption>Diagram (not a screenshot): the connection links the computers; Remote Desktop shows the office screen; Tally runs on the office computer.</figcaption>
</figure>""".replace("{red}", cfg["brand_red"])

subs = {
    "title": cfg["title"], "version": cfg["version"], "date": cfg["date"],
    "support_contact": cfg["support_contact"],
    "support_email_line": (" · " + cfg["support_email"]) if cfg.get("support_email") else "",
    "diagram": "DIAGRAM_PLACEHOLDER", "help_topics": help_body,
}
md = md_src
for k, v in subs.items():
    md = md.replace("{{" + k + "}}", v)

import markdown  # pip install markdown
body = markdown.markdown(md, extensions=["tables", "sane_lists"])
body = body.replace("<p>DIAGRAM_PLACEHOLDER</p>", DIAGRAM)

page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(cfg['title'])}</title>
<style>
:root{{--red:{cfg['brand_red']};--ink:#1f2328;--muted:#6b7280;--line:#e5e7eb}}
body{{font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif;color:var(--ink);margin:0;background:#fff;line-height:1.5}}
header{{background:var(--red);color:#fff;padding:22px 32px}}header .b{{font-size:24px;font-weight:800}}header .s{{opacity:.9;font-size:14px}}
main{{max-width:820px;margin:0 auto;padding:24px 32px 48px;font-size:15px}}
h1{{font-size:26px;margin:.2em 0}}h2{{font-size:20px;margin-top:1.6em;border-bottom:2px solid var(--red);padding-bottom:4px}}h3{{font-size:16px;margin-top:1.3em}}
table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}}th,td{{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}}th{{background:#f7f7f8}}
blockquote{{border-left:4px solid var(--red);margin:12px 0;padding:6px 14px;background:#fff7f7;color:#4b5563}}
figure.diagram{{margin:16px 0;border:1px solid var(--line);border-radius:8px;padding:12px}}figcaption{{font-size:12px;color:var(--muted);text-align:center}}
code{{background:#f3f4f6;padding:1px 4px;border-radius:3px}}
footer{{color:var(--muted);font-size:12px;text-align:center;padding:16px}}
@media print{{header{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}h2{{page-break-after:avoid}}table,figure{{page-break-inside:avoid}}}}
</style></head><body>
<header><div class="b">DishNet <span style="font-weight:400">Secure Connect</span></div><div class="s">Customer Setup Guide · version {html.escape(cfg['version'])} · {html.escape(cfg['date'])}</div></header>
<main>{body}</main>
<footer>Encrypted connection · Authorised devices only · Powered by WireGuard® (a registered trademark of Jason A. Donenfeld) · © DishNet Africa</footer>
</body></html>"""

out_html = ROOT / "docs/manual/customer-setup-guide.html"
out_html.write_text(page)
srv = ROOT / "server/internal/api/manual"
srv.mkdir(parents=True, exist_ok=True)
(srv / "guide.html").write_text(page)
print("wrote", out_html)

chromium = os.environ.get("CHROMIUM") or shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
if not chromium:
    for c in sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")):
        chromium = c
if not chromium:
    print("no Chromium found; PDF not built (set CHROMIUM=...)"); sys.exit(0)
out_pdf = ROOT / "docs/manual/customer-setup-guide.pdf"
cmd = [chromium, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer", f"--print-to-pdf={out_pdf}", out_html.resolve().as_uri()]
subprocess.run(cmd, check=True, capture_output=True)
shutil.copy(out_pdf, srv / "guide.pdf")
print("wrote", out_pdf, out_pdf.stat().st_size, "bytes")
