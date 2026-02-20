#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import SECRET_KEY, APP_TITLE


app = Flask(__name__)
app.secret_key = SECRET_KEY

# reverse proxy arkasında doğru scheme/host algılansın
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


@app.get("/health")
def health():
    return "OK"


@app.get("/")
def home():
    return f"{APP_TITLE} (ikapp test) OK"
