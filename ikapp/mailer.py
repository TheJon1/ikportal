#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .app_instance import app
from .config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM, APP_TITLE
from .db import query_one, query_all
from .utils import html_escape, nl2br

from .config import ROLE_OWNER, ROLE_ACCOUNTING, ROLE_IT

def send_mail(to_email: str, subject: str, body_html: str):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = MAIL_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(MAIL_FROM, [to_email], msg.as_string())
    except Exception as e:
        try:
            app.logger.exception("Mail gönderilemedi: %s", e)
        except Exception:
            print("Mail gönderilemedi:", e)

def send_mail_many(to_addrs, subject: str, body: str):
    if not to_addrs:
        return
    for a in to_addrs:
        try:
            send_mail(a, subject, body)
        except Exception:
            pass

def get_owner_email():
    r = query_one("SELECT email FROM users WHERE role=? AND is_active=1 ORDER BY id ASC LIMIT 1", (ROLE_OWNER,))
    return (r["email"] if r else "") or ""

def get_accounting_emails():
    rows = query_all("SELECT email FROM users WHERE role=? AND is_active=1 AND email IS NOT NULL AND email!=''", (ROLE_ACCOUNTING,))
    return [r["email"] for r in rows]

def get_it_emails():
    rows = query_all(
        "SELECT email FROM users WHERE role=? AND is_active=1 AND email IS NOT NULL AND email!=''",
        (ROLE_IT,)
    )
    return [r["email"] for r in rows]

def get_user_email(user_id: int):
    r = query_one("SELECT email FROM users WHERE id=? AND is_active=1", (user_id,))
    return (r["email"] if r else "") or ""

def ik_mail_template(title: str, intro: str, rows: list, stage_text: str = "", button_text: str = "", button_url: str = "", footer: str = "İK Portal"):
    tr_html = ""
    for k, v in rows:
        tr_html += f"""
        <tr>
          <td style="padding:7px 0; color:#64748b; width:140px; vertical-align:top;">{html_escape(str(k))}</td>
          <td style="padding:7px 0; font-weight:700;">{v}</td>
        </tr>
        """

    stage_block = ""
    if stage_text:
        stage_block = f"""
        <div style="margin-top:14px; border:1px solid #e5e7eb; border-radius:12px; padding:12px 14px; background:#ffffff;">
          <div style="font-weight:800; margin-bottom:8px;">Onay Aşaması</div>
          <div style="margin-bottom:10px;">
            <span style="display:inline-block; padding:6px 12px; border-radius:999px; background:#fff7ed; border:1px solid #fed7aa; color:#9a3412; font-weight:800;">
              {html_escape(stage_text)}
            </span>
          </div>
          {"<a href='"+html_escape(button_url)+"' style='display:inline-block; padding:10px 14px; border-radius:12px; background:#1d4ed8; color:#ffffff; font-weight:800; text-decoration:none;'>"+html_escape(button_text)+"</a>" if (button_text and button_url) else ""}
          {("<div style='margin-top:10px; font-size:12px; color:#64748b;'>Buton çalışmazsa link: "+html_escape(button_url)+"</div>") if (button_text and button_url) else ""}
        </div>
        """

    return f"""
<div style="font-family:Segoe UI,Roboto,Arial; font-size:14px; color:#0f172a; background:#f6f8fc; padding:16px 0;">
  <div style="max-width:680px; margin:0 auto; border:1px solid #e5e7eb; border-radius:14px; overflow:hidden; background:#ffffff;">
    <div style="background:#1d4ed8; color:white; padding:16px 18px;">
      <div style="font-size:16px; font-weight:900; letter-spacing:.2px;">{html_escape(APP_TITLE)}</div>
      <div style="opacity:.92; margin-top:4px;">{html_escape(title)}</div>
    </div>

    <div style="padding:18px;">
      <p style="margin:0 0 10px 0;">Merhaba,</p>
      <p style="margin:0 0 14px 0; color:#334155;">{html_escape(intro)}</p>

      <div style="border:1px solid #e5e7eb; border-radius:12px; padding:12px 14px; background:#f8fafc;">
        <div style="font-weight:900; margin-bottom:8px;">Talep Bilgileri</div>
        <table style="width:100%; border-collapse:collapse; font-size:14px;">
          {tr_html}
        </table>
      </div>

      {stage_block}

      <div style="margin-top:16px; color:#94a3b8; font-size:12px;">
        {html_escape(footer)}
      </div>
    </div>
  </div>
</div>
"""
