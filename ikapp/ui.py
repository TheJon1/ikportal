#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import session
from .config import (
    APP_TITLE,
    ROLE_OWNER, ROLE_ACCOUNTING, ROLE_MANAGER, ROLE_PERSONNEL, ROLE_RESPONSIBLE, ROLE_IT,
    STATUS_APPROVED, STATUS_REJECTED, ADV_STATUS_APPROVED, ADV_STATUS_REJECTED
)
from .utils import html_escape
from .auth import current_user

def format_status_pill(status: str) -> str:
    s = status or ""
    cls = "warn"
    if s == STATUS_APPROVED or s == ADV_STATUS_APPROVED:
        cls = "ok"
    elif s == STATUS_REJECTED or s == ADV_STATUS_REJECTED:
        cls = "bad"
    return f"<span class='pill {cls}'>{html_escape(s)}</span>"

def render_page(title, body_html, user=None):
    u = user or current_user()
    nav = ""
    if u:
        nav_items = [
            ("/", "Ana Sayfa"),
        ]

        if u["role"] != ROLE_OWNER:
            nav_items.append(("/leave/my", "İzinlerim"))
            nav_items.append(("/leave/new", "İzin Talep Et"))

        if u["can_qr"] == 1:
            nav_items.append(("/qr", "QR ile Mesai"))

        if u["role"] in (ROLE_OWNER, ROLE_ACCOUNTING, ROLE_MANAGER, ROLE_RESPONSIBLE):
            nav_items.append(("/leave/admin", "İzin Yönetimi"))

        if u["role"] in (ROLE_OWNER, ROLE_ACCOUNTING):
            nav_items.append(("/attendance", "Mesai Raporu"))

        if u["role"] == ROLE_RESPONSIBLE:
            nav_items.append(("/attendance/team", "Mesai (Ekibim)"))

        if u["role"] in (ROLE_OWNER, ROLE_ACCOUNTING, ROLE_MANAGER, ROLE_RESPONSIBLE):
            nav_items.append(("/assets", "Zimmet Yönetimi"))

        if u["role"] != ROLE_OWNER:
            nav_items.append(("/advance/my", "Avanslarım"))
            nav_items.append(("/advance/new", "Avans Talep Et"))

        nav_items.append(("/it/my", "IT Taleplerim"))
        nav_items.append(("/it/new", "IT Talep Aç"))

        nav_items.append(("/reminders", "Hatırlatmalar"))

        if u["role"] == ROLE_IT:
            nav_items.append(("/it/admin", "IT Talep Yönetimi"))

        if u["role"] == ROLE_ACCOUNTING:
            nav_items.append(("/advance/accounting", "Avans Yönetimi"))

        if u["role"] == ROLE_OWNER:
            nav_items.append(("/advance/owner", "Avans Onay"))

        if u["role"] in (ROLE_OWNER, ROLE_ACCOUNTING):
            nav_items.append(("/users", "Kullanıcılar"))

        nav_links = "".join([f"<a class='navlink' href='{href}'>{html_escape(text)}</a>" for href, text in nav_items])

        nav = f"""
        <div class="topbar">
          <div class="brand">{APP_TITLE}</div>

          <input id="navToggle" class="navToggle" type="checkbox">
          <label class="hamburger" for="navToggle" aria-label="Menüyü Aç/Kapat">
            <span></span><span></span><span></span>
          </label>

          <div class="nav" id="topNav">{nav_links}</div>

          <div class="userbox">
            <span class="muted userName">{html_escape(u['full_name'])}</span>
            <a class="navlink" href="/logout">Çıkış</a>
          </div>
        </div>
        """
    else:
        nav = f"""
        <div class="topbar">
          <div class="brand">{APP_TITLE}</div>
          <div class="nav"></div>
          <div class="userbox"></div>
        </div>
        """

    return f"""
    <!doctype html>
    <html lang="tr">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>{html_escape(title)} - {APP_TITLE}</title>
      <style>
        :root {{
          --bg:#f6f8fc;
          --card:#ffffff;
          --text:#0f172a;
          --muted:#64748b;
          --line:rgba(15,23,42,.10);
          --primary:#1d4ed8;
          --primary2:#1e40af;
          --ok:#16a34a;
          --bad:#dc2626;
          --warn:#f59e0b;
          --shadow: 0 10px 28px rgba(2,6,23,.08);
        }}
        *{{box-sizing:border-box}}
        body{{margin:0;background:linear-gradient(180deg,#eef3ff,var(--bg));color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;}}
        a{{color:var(--primary);text-decoration:none}}
        .topbar{{
          display:flex; gap:12px; align-items:center; justify-content:space-between;
          padding:14px 18px; border-bottom:1px solid var(--line);
          background:rgba(255,255,255,.85); backdrop-filter: blur(8px);
          position:sticky; top:0; z-index:10;
          flex-wrap:wrap;
        }}
        .brand{{font-weight:800;letter-spacing:.2px; white-space:nowrap}}
        .nav{{display:flex;gap:10px;flex-wrap:wrap}}
        .navlink{{padding:8px 10px;border:1px solid var(--line);border-radius:12px;background:#fff; white-space:nowrap}}
        .navlink:hover{{background:#f3f6ff}}
        .userbox{{display:flex;align-items:center;gap:10px; flex-wrap:wrap; justify-content:flex-end}}
        .container{{max-width:1100px;margin:22px auto;padding:0 14px}}
        .card{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:var(--shadow)}}
        .grid{{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}}
        .two{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
        .h1{{font-size:20px;font-weight:800;margin:0 0 10px}}
        .muted{{color:var(--muted)}}
        input,select,textarea{{width:100%;padding:10px 12px;border-radius:12px;border:1px solid var(--line);background:#fff;color:var(--text);outline:none}}
        textarea{{min-height:90px;resize:vertical}}
        .row{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
        .btn{{display:inline-block;padding:10px 14px;border-radius:12px;border:1px solid rgba(29,78,216,.20);background:linear-gradient(180deg,var(--primary),var(--primary2));color:white;font-weight:700;cursor:pointer}}
        .btn:hover{{filter:brightness(1.05)}}
        .btn2{{display:inline-block;padding:10px 14px;border-radius:12px;border:1px solid var(--line);background:#fff;color:var(--text);font-weight:700}}
        .btn2:hover{{background:#f3f6ff}}

        table{{width:100%;border-collapse:collapse;display:block;overflow-x:auto;max-width:100%;-webkit-overflow-scrolling:touch}}
        th,td{{border-bottom:1px solid var(--line);padding:10px 8px;text-align:left;font-size:14px;white-space:nowrap}}

        .pill{{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid var(--line);background:#fff;font-size:12px}}
        .pill.ok{{border-color:rgba(22,163,74,.25);background:rgba(22,163,74,.08);color:var(--ok)}}
        .pill.bad{{border-color:rgba(220,38,38,.25);background:rgba(220,38,38,.08);color:var(--bad)}}
        .pill.warn{{border-color:rgba(245,158,11,.25);background:rgba(245,158,11,.10);color:#92400e}}
        .note{{border:1px dashed var(--line);background:#fbfdff;padding:12px;border-radius:14px}}

        .navToggle{{display:none}}
        .hamburger{{
          display:none;
          width:42px; height:38px;
          border:1px solid var(--line);
          border-radius:12px;
          background:#fff;
          align-items:center;
          justify-content:center;
          gap:5px;
          cursor:pointer;
        }}
        .hamburger span{{
          display:block;
          width:18px;
          height:2px;
          background:rgba(15,23,42,.70);
          border-radius:2px;
        }}

        @media (max-width:900px){{
          .row{{grid-template-columns:1fr}}
          .two{{grid-template-columns:1fr}}
          .hamburger{{display:flex}}
          .nav{{
            width:100%;
            display:none;
            padding:10px 0 2px;
            border-top:1px solid var(--line);
          }}
          .navlink{{padding:10px 12px}}
          .navToggle:checked ~ .nav{{display:flex}}
          .userName{{display:none}}
        }}

        @media (max-width:520px){{
          .container{{margin:16px auto}}
          .topbar{{padding:12px 12px}}
          .brand{{font-size:14px}}
          .btn,.btn2{{width:100%; text-align:center}}
        }}
      </style>
    </head>
    <body>
      {nav}
      <div class="container">
        {body_html}
      </div>
    </body>
    </html>
    """
