# osint_scout_flask.py
# OSINT Scout — Flask web app (v3.1) with Family Tree pivots, CentralOps IP checks, Google dorks & Basic Auth

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

# ---------- Basic Auth ----------
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

# ---------- HTTP ----------
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT}
HTTP_TIMEOUT = 8
NET_DELAY = 0.6

# ---------- Catalogs ----------
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
    ("CentralOps Domain Dossier", "https://centralops.net/co/DomainDossier.aspx?addr={t}&dom_dns=1&dom_whois=1&net_whois=1"),
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
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("WhoCallsMe", "https://whocallsme.com/Phone-Number.aspx/{p}"),
    ("800notes", "https://800notes.com/Phone.aspx/{p}"),
]

# ---------- Family tree / genealogy pivots ----------
FAMILY_SITES = [
    ("Ancestry (search)", "https://www.ancestry.com/search/?name={name_q}&birth={by}&death={dy}&keywords={kw}"),
    ("FamilySearch (search)", "https://www.familysearch.org/en/search/record/results?q.givenName={name_q}&q.surname={surname_q}&q.birthLikeDate.from={by}&q.deathLikeDate.from={dy}"),
    ("MyHeritage (search)", "https://www.myheritage.com/research?s=1&formId=master&formMode=1&action=person&firstName={name_q}&lastName={surname_q}&birthYear={by}&deathYear={dy}"),
    ("Find a Grave (search)", "https://www.findagrave.com/memorial/search?firstname={name_q}&lastname={surname_q}&birthyear={by}&deathyear={dy}"),
    ("Newspapers.com (search)", "https://www.newspapers.com/search/?query={name_q}%20{surname_q}%20{city}%20{state}%20{by}%20{dy}"),
    ("Whitepages*", "https://www.whitepages.com/name/{name_dash}/{state}"),
    ("TruePeopleSearch*", "https://www.truepeoplesearch.com/results?name={name_q}%20{surname_q}&citystatezip={city}%20{state}"),
    ("Spokeo*", "https://www.spokeo.com/{name_dash}/{state}"),
]

# ---------- Google dorks ----------
GOOGLE_DORKS = {
    "name": [
        '"{name}" {city} {state} site:facebook.com',
        '"{name}" {city} {state} site:linkedin.com',
        '"{name}" {city} {state} filetype:pdf',
        '"{name}" {city} {state} site:youtube.com',
        '"{name}" {city} {state} "resume" OR "CV" filetype:pdf',
    ],
    "username": [
        'site:github.com "{u}"',
        'site:pastebin.com "{u}"',
        'site:reddit.com "u/{u}" OR "{u}"',
        '"{u}" "@{u}" site:twitter.com OR site:x.com OR site:instagram.com',
    ],
    "email": [
        '"{email}" filetype:pdf',
        '"{email}" site:pastebin.com',
        '"{email}" "password" OR "leak"',
        'site:github.com "{email}"',
    ],
    "phone": [
        '"{phone}" site:800notes.com OR site:whocallsme.com',
        '"{phone}" "scam" OR "complaint"',
        'filetype:txt "{phone}"',
    ],
    "domain": [
        'site:{domain} -www.{domain}',
        '"{domain}" "password" OR "credentials" filetype:txt',
        'site:pastebin.com {domain}',
        'site:github.com {domain}',
    ],
    "ip": [
        '"{ip}" "malware" OR "botnet"',
        '"{ip}" filetype:log OR filetype:txt',
        '"{ip}" site:pastebin.com',
    ],
    "family": [
        '"{name}" {surname} {city} {state} obituary',
        '"{name}" {surname} obituary "{relative}"',
        '"{name}" {surname} "mother" OR "father" OR "brother" OR "sister" {city} {state}',
        '"{name}" {surname} marriage license {state}',
        '"{name}" {surname} site:newspapers.com',
        '"{name}" {surname} site:findagrave.com',
        '"{name}" {surname} site:familysearch.org',
        '"{name}" {surname} genealogy {city} {state}',
    ],
}

# ---------- Helpers ----------
def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D+", "", raw or "")
    if not digits:
        return ""
    if digits.startswith("1") and len(digits) == 11:
        return "+" + digits
    if len(digits) == 10:
        return "+1" + digits
    return "+" + digits

def http_check(url: str):
    try:
        resp = requests.head(url, headers=HEADERS, allow_redirects=True, timeout=HTTP_TIMEOUT)
        code = resp.status_code
        final = resp.url
        if code >= 400 or code in (403, 405):
            resp = requests.get(url, headers=HEADERS, allow_redirects=True, timeout=HTTP_TIMEOUT)
            code = resp.status_code
            final = resp.url
        return {"status_code": code, "final_url": final}
    except Exception as e:
        return {"error": str(e)}

def exif_from_bytes(data: bytes):
    try:
        img = Image.open(BytesIO(data))
        exif = img.getexif()
        if not exif:
            return {}
        return {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    except Exception:
        return {}

def g(q: str) -> str:
    return f"https://www.google.com/search?q={urllib.parse.quote_plus(q)}"

def _q(s: str) -> str:
    return urllib.parse.quote_plus(s or "")

def _dash_name(full_name: str) -> str:
    return re.sub(r"\s+", "-", (full_name or "").strip())

# ---------- Routes ----------
@app.route('/')
@require_basic_auth
def index():
    # (UI template omitted here for brevity in this snippet — keep your existing INDEX_HTML)
    return render_template_string(INDEX_HTML)

# ... rest of your routes (api_pivots, api_check_username, api_exif, api_report) remain same ...
