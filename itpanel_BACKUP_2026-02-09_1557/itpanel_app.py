#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import uuid
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sqlite3, os
from functools import wraps
from flask import session, redirect, request, g

IK_DB_PATH = os.environ.get("IK_DB_PATH", "/home/ubuntu2026/ik/ik.db")

def ik_db():
    if "ik_db" not in g:
        g.ik_db = sqlite3.connect(IK_DB_PATH)
        g.ik_db.row_factory = sqlite3.Row
    return g.ik_db

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    row = ik_db().execute("SELECT id, username, full_name, role, is_active FROM users WHERE id=?", (uid,)).fetchone()
    if not row or row["is_active"] != 1:
        return None
    return row

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return redirect(f"/login?next={request.path}")
        g.user = u
        return f(*args, **kwargs)
    return wrapper

def it_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return redirect(f"/login?next={request.path}")
        if u["role"] != "it":
            return ("Yetkisiz", 403)
        g.user = u
        return f(*args, **kwargs)
    return wrapper

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import StringField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired, Length, Email
from PIL import Image

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("ITPANEL_SECRET", "change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(INSTANCE_DIR, "itpanel.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB

@app.teardown_appcontext
def close_ik_db(exc):
    db = g.pop("ik_db", None)
    if db:
        db.close()


db = SQLAlchemy(app)
# DB tablolarını uygulama açılır açılmaz oluştur (Flask 3 uyumlu)
with app.app_context():
    db.create_all()


# -------------------------------------------------
# MODEL
# -------------------------------------------------
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_no = db.Column(db.String(32), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    attachment_name = db.Column(db.String(255))
    attachment_path = db.Column(db.String(255))
    status = db.Column(db.String(20), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email = db.Column(db.String(255), index=True)
    access_token = db.Column(db.String(64), index=True)
    status_note = db.Column(db.Text)
    status_updated_at = db.Column(db.String(32))

# -------------------------------------------------
# FORM
# -------------------------------------------------
class TicketForm(FlaskForm):
    full_name = StringField("Ad Soyad", validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField("E-posta", validators=[DataRequired(), Email(), Length(max=255)])
    priority = SelectField(
        "Önem Derecesi",
        choices=[
            ("low", "Düşük"),
            ("medium", "Orta"),
            ("high", "Yüksek"),
            ("critical", "Kritik")
        ],
        validators=[DataRequired()]
    )
    subject = StringField("Konu Başlığı", validators=[DataRequired(), Length(min=3, max=200)])
    description = TextAreaField("Açıklama", validators=[DataRequired(), Length(min=5)])
    attachment = FileField("Görsel (opsiyonel)")

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def make_ticket_no(ticket_id):
    return f"IT-{datetime.utcnow().year}-{ticket_id:06d}"

def save_image(file):
    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[1].lower()
    new_name = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(UPLOAD_DIR, new_name)

    img = Image.open(file.stream)
    img.verify()
    file.stream.seek(0)

    img = Image.open(file.stream)
    if ext in ("jpg", "jpeg"):
        img = img.convert("RGB")

    if max(img.size) > 1600:
        ratio = 1600 / max(img.size)
        img = img.resize((int(img.size[0] * ratio), int(img.size[1] * ratio)))

    img.save(path)
    return new_name, filename

def send_mail(ticket):
    host = os.environ.get("ITPANEL_SMTP_HOST")
    port = os.environ.get("ITPANEL_SMTP_PORT")
    user = os.environ.get("ITPANEL_SMTP_USER")
    pwd = os.environ.get("ITPANEL_SMTP_PASS")
    recipients = os.environ.get("ITPANEL_IT_RECIPIENTS", "")

    if not host or not port or not recipients:
        return

    to_list = [x.strip() for x in recipients.split(",") if x.strip()]

    msg = MIMEMultipart()
    msg["From"] = user or "itpanel@localhost"
    msg["To"] = ", ".join(to_list)
    msg["Subject"] = f"[IT TALEP] {ticket.ticket_no}"

    body = f"""
Yeni IT talebi oluşturuldu.

Talep No: {ticket.ticket_no}
Ad Soyad: {ticket.full_name}
Önem: {ticket.priority}
Konu: {ticket.subject}

Açıklama:
{ticket.description}
"""
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        s = smtplib.SMTP(host, int(port), timeout=15)
        s.starttls()
        if user and pwd:
            s.login(user, pwd)
        s.sendmail(msg["From"], to_list, msg.as_string())
        s.quit()
    except Exception as e:
        print("MAIL ERROR:", e)

# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route("/")
def index():
    # Herkes talep açabilsin; listeyi sadece IT görsün
    return redirect(url_for("create_ticket"))

@app.route("/talep", methods=["GET", "POST"])
def create_ticket():
    form = TicketForm()

    if request.method == "POST":
        if not form.validate_on_submit():
            flash("Lütfen zorunlu alanları doğru doldurun.", "danger")
            return render_template("create_ticket.html", form=form)

        ticket = Ticket(
            ticket_no="TEMP",
            access_token=uuid.uuid4().hex,
            full_name=form.full_name.data.strip(),
            email=form.email.data.strip().lower(),
            priority=form.priority.data,
            subject=form.subject.data.strip(),
            description=form.description.data.strip(),
            status="open"
        )

        file = request.files.get("attachment")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Sadece png/jpg/jpeg/webp görseller yüklenebilir.", "danger")
                return render_template("create_ticket.html", form=form)
            try:
                saved_name, original_name = save_image(file)
                ticket.attachment_path = saved_name
                ticket.attachment_name = original_name
            except Exception:
                flash("Görsel okunamadı. Lütfen geçerli bir görsel yükleyin.", "danger")
                return render_template("create_ticket.html", form=form)

        db.session.add(ticket)
        db.session.commit()

        ticket.ticket_no = make_ticket_no(ticket.id)
        db.session.commit()

        # IT ekibine mail
        send_mail(ticket)
        # Talep açan kişiye mail (token’lı link)
        send_requester_mail(ticket)

        flash(f"Talebiniz oluşturuldu: {ticket.ticket_no}", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id, k=ticket.access_token))

    # GET isteğinde form sayfasını göster
    return render_template("create_ticket.html", form=form)


def send_requester_mail(ticket):
    host = os.environ.get("ITPANEL_SMTP_HOST")
    port = os.environ.get("ITPANEL_SMTP_PORT")
    user = os.environ.get("ITPANEL_SMTP_USER")
    pwd = os.environ.get("ITPANEL_SMTP_PASS")

    # SMTP ayarı yoksa sessizce geç
    if not host or not port:
        return

    if not ticket.email:
        return

    # Kullanıcının özel linki (token ile)
    link = f"http://{request.host}/talep/{ticket.id}?k={ticket.access_token}"

    msg = MIMEMultipart()
    msg["From"] = user or "itpanel@localhost"
    msg["To"] = ticket.email
    msg["Subject"] = f"Talebiniz alındı: {ticket.ticket_no}"

    body = f"""
Merhaba {ticket.full_name},

Talebiniz oluşturuldu.

Talep No: {ticket.ticket_no}
Önem: {ticket.priority}
Konu: {ticket.subject}

Talebinizi görüntülemek için link:
{link}

Not: Bu link size özeldir.
"""
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        s = smtplib.SMTP(host, int(port), timeout=15)
        s.ehlo()
        s.starttls()
        s.ehlo()
        if user and pwd:
            s.login(user, pwd)
        s.sendmail(msg["From"], [ticket.email], msg.as_string())
        s.quit()
    except Exception as e:
        print("REQUESTER MAIL ERROR:", e)

def send_status_update_mail(ticket, old_status, new_status, note):
    host = os.environ.get("ITPANEL_SMTP_HOST")
    port = os.environ.get("ITPANEL_SMTP_PORT")
    user = os.environ.get("ITPANEL_SMTP_USER")
    pwd = os.environ.get("ITPANEL_SMTP_PASS")

    if not host or not port or not ticket.email:
        return

    msg = MIMEMultipart()
    msg["From"] = user or "itpanel@localhost"
    msg["To"] = ticket.email
    msg["Subject"] = f"Talep Durumu Güncellendi: {ticket.ticket_no}"

    body = f"""
Merhaba {ticket.full_name},

Talebinizin durumu güncellendi.

Talep No: {ticket.ticket_no}
Eski Durum: {old_status}
Yeni Durum: {new_status}

IT Açıklaması:
{note or "-"}

Not: Talep linkiniz (size özel) sizdeki mailde bulunmaktadır.
"""
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        s = smtplib.SMTP(host, int(port), timeout=15)
        s.ehlo()
        s.starttls()
        s.ehlo()
        if user and pwd:
            s.login(user, pwd)
        s.sendmail(msg["From"], [ticket.email], msg.as_string())
        s.quit()
    except Exception as e:
        print("STATUS MAIL ERROR:", e)


from urllib.parse import quote

@app.route("/login")
def login():
    # IT panel içinden gelen isteklerde "next" yoksa /it/’ye dönsün
    nxt = request.args.get("next")
    if not nxt:
        # DispatcherMiddleware altında script_root genelde "/it" olur
        sr = request.script_root or "/it"
        nxt = sr + "/"
    return redirect(f"/login?next={quote(nxt, safe='/:?=&')}")

@app.get("/logout")
def logout():
    return redirect("/logout")

@app.get("/")
def it_tickets():
    if not current_user():
        return redirect(f"/login?next={request.path}")

    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    return render_template("index.html", tickets=tickets)

@app.post("/ticket/<int:ticket_id>/update")
def it_update_ticket(ticket_id):
    if not current_user():
        return redirect(f"/login?next={request.script_root}{request.path}")

    ticket = Ticket.query.get_or_404(ticket_id)

    new_status = request.form.get("status", "").strip()
    note = request.form.get("status_note", "").strip()

    allowed = {"open", "pending", "forwarded", "closed"}
    if new_status not in allowed:
        flash("Geçersiz durum.", "danger")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    old_status = ticket.status
    ticket.status = new_status
    ticket.status_note = note
    ticket.status_updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    db.session.commit()

    # durum değiştiyse kullanıcıya mail at
    if ticket.email and old_status != new_status:
        send_status_update_mail(ticket, old_status, new_status, note)

    flash("Talep güncellendi.", "success")
    return redirect(url_for("ticket_detail", ticket_id=ticket.id))

@app.route("/talep/<int:ticket_id>")
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Login olan kullanıcı detay görebilir
    if current_user():
        return render_template("ticket_detail.html", ticket=ticket)

    # Login yoksa token ile görebilir
    key = request.args.get("k", "")
    if not key or key != (ticket.access_token or ""):
        abort(403)

    return render_template("ticket_detail.html", ticket=ticket)

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4996, debug=True)
