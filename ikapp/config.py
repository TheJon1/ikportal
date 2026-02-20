#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

# -----------------------------
# CONFIG
# -----------------------------
APP_TITLE = "İK Portal"
DB_PATH = os.environ.get("IK_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "ik.db"))
SECRET_KEY = os.environ.get("IK_SECRET_KEY", "saDfasdwqefgdsvcxzfasdRqweasDASFGA")

# SMTP (systemd env ile ver; yoksa mail sessizce pas geçer)
SMTP_HOST = os.environ.get("IK_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("IK_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("IK_SMTP_USER", "")
SMTP_PASS = os.environ.get("IK_SMTP_PASS", "")
MAIL_FROM  = os.environ.get("IK_MAIL_FROM", SMTP_USER)

QR_COOLDOWN_MINUTES = int(os.environ.get("IK_QR_COOLDOWN_MINUTES", "10"))

# Upload
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "uploads", "it")
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}

# Roles
ROLE_OWNER = "owner"
ROLE_ACCOUNTING = "accounting"
ROLE_MANAGER = "manager"
ROLE_PERSONNEL = "personnel"
ROLE_RESPONSIBLE = "responsible"
ROLE_IT = "it"
ALLOWED_ROLES = {ROLE_OWNER, ROLE_ACCOUNTING, ROLE_MANAGER, ROLE_PERSONNEL, ROLE_RESPONSIBLE, ROLE_IT}

# Attendance types
TUR_GIRIS = "GIRIS"
TUR_OGLE_CIKIS = "OGLE_CIKIS"
TUR_OGLE_GIRIS = "OGLE_GIRIS"
TUR_CIKIS = "CIKIS"
TUR_SEQUENCE = [TUR_GIRIS, TUR_OGLE_CIKIS, TUR_OGLE_GIRIS, TUR_CIKIS]
TUR_LABEL = {
    TUR_GIRIS: "Giriş",
    TUR_OGLE_CIKIS: "Öğle Çıkış",
    TUR_OGLE_GIRIS: "Öğle Giriş",
    TUR_CIKIS: "Çıkış",
}

# Leave statuses
STATUS_PENDING = "Beklemede"
STATUS_APPROVED = "Onaylandi"
STATUS_REJECTED = "Reddedildi"

# Advance statuses
ADV_STATUS_PENDING = "Beklemede"
ADV_STATUS_SENT_TO_OWNER = "PatronOnayinda"
ADV_STATUS_APPROVED = "Onaylandi"
ADV_STATUS_REJECTED = "Reddedildi"

# Leave stages
STAGE_RESPONSIBLE = "RESPONSIBLE"
STAGE_MANAGER = "MANAGER"
STAGE_OWNER = "OWNER"
STAGE_DONE = "DONE"

# IT
IT_PRIORITIES = ["Düşük", "Orta", "Yüksek", "Acil"]
IT_STATUSES = ["Açık", "Beklemede", "Yönlendirildi", "Kapalı"]
