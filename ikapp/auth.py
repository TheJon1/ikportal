#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import session, redirect, url_for, request, abort
from .db import query_one

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return query_one("SELECT * FROM users WHERE id=? AND is_active=1", (uid,))

def login_required(fn):
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def role_required(*roles):
    def deco(fn):
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if u["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco
