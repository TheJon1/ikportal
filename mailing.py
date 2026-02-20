#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def _smtp_config():
    # SMTP (systemd env ile ver; yoksa mail sessizce pas geçer)
    host = os.environ.get("IK_SMTP_HOST", "")
    port = int(os.environ.get("IK_SMTP_PORT", "587"))
    user = os.environ.get("IK_SMTP_USER", "")
    pwd  = os.environ.get("IK_SMTP_PASS", "")
    mail_from = os.environ.get("IK_MAIL_FROM", user)
    return host, port, user, pwd, mail_from


def send_mail(to_email: str, subject: str, body_html: str):
    host, port, user, pwd, mail_from = _smtp_config()

    if not host or not user or not pwd:
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = mail_from
        msg["To"] = to_email

        msg.attach(MIMEText(body_html, "html", "utf-8"))

        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(user, pwd)
            s.sendmail(mail_from, [to_email], msg.as_string())

    except Exception as e:
        # Mail atılamadı diye işlem çökmesin
        try:
            print("Mail gönderilemedi:", repr(e), flush=True)
        except Exception:
            pass
        return


def send_mail_many(to_addrs, subject: str, body: str):
    if not to_addrs:
        return
    for a in to_addrs:
        try:
            send_mail(a, subject, body)
        except Exception:
            pass
