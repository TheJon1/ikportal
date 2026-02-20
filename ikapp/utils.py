#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from flask import request
from .config import ALLOWED_IMAGE_EXT

def allowed_image(filename):
    if not filename:
        return False
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT

def public_base_url():
    host = request.host
    return f"https://{host}"

def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def nl2br(s: str) -> str:
    return html_escape(s).replace("\n", "<br>")

def device_fingerprint():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
    if "," in ip:
        ip = ip.split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")[:180]
    return ip.strip(), ua.strip()
