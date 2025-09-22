# osint_scout_flask.py
# OSINT Scout — Flask web app (v2) with Google dorks & Basic Auth
# Save this file as osint_scout_flask.py and deploy (Render, Heroku, etc.)
# Required env vars for public deployment:
#   APP_USER (optional) and APP_PASS (optional) for Basic Auth
#
# Local run:
#   python -m venv .venv
#   .venv\\Scripts\\activate    # Windows PowerShell
#   pip install -r requirements.txt
#   python osint_scout_flask.py
# Then open http://localhost:5000

from flask import Flask, render_template_string, request, jsonify, Response
import requests
from PIL import Image, ExifTags
from io import BytesIO
import re
import time
from datetime import datetime
import os
from functools import wraps
import urllib.parse

app = Flask(__name__)

# ----- Basic Auth (set env vars APP_USER and APP_PASS on Render if you want protection) -----
APP_USER = os.getenv("APP_USER")
APP_PASS = os.getenv("APP_PASS")

def require_basic_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if APP_USER and APP_PASS:
            auth = request.authorization
            if not auth or not (auth.username == APP_USER and auth.password == APP_PASS):
                return Response(
                    "Authentication required",
                    401,
                    {"WWW-Authenticate": 'Basic realm="OSINT Scout"'}
                )
        return f(*args, **kwargs)
    return wrapper

# ----- HTTP config -----
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT}
HTTP_TIMEOUT = 8
NET_DELAY = 0.6

# ----- Catalogs -----
USERNAME_SITES = [
    ("Facebook", "https://www.facebook.com/{u}"),
    ("Instagram", "https://www.instagram.com/{u}"),
    ("X (Twitter)", "https://x.com/{u}"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("Twitch", "https://www.twitch.tv/{u}"),
    ("GitHub", "https://github.com/{u}"),
    ("Steam", "https://steamcommunity.com/id/{u}"),
]

DOMAIN_LINKS = [
    ("SecurityTrails", "https://securitytrails.com/domain/{t}"),
    ("crt.sh", "https://crt.sh/?q={t}"),
    ("Wayback", "https://web.archive.org/web/*/{t}"),
]

IP_LINKS = [
    ("Shodan", "https://www.shodan.io/host/{t}"),
    ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{t}"),
]

EMAIL_LINKS = [
    ("Google", "https://www.google.com/search?q={q}"),
    ("Bing", "https://www.bing.com/search?q={q}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("HaveIBeenPwned", "https://haveibeenpwned.com/"),
    ("Gravatar", "https://en.gravatar.com/site/check/{e}"),
    ("GitHub code search", "https://github.com/search?q={q}"),
    ("Pastebin search", "https://pastebin.com/search?q={q}"),
]

PHONE_LINKS = [
    ("Google", "https://www.google.com/search?q={q}"),
    ("Bing", "https://www.bing.com/search?q={q}"),
    ("DuckDuckGo", "htt

