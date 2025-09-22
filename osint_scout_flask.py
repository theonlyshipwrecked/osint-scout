# OSINT Scout - Flask web app (with Basic Auth) - v2
# Supports "Build Pivots" with ANY single field.

from flask import Flask, render_template_string, request, jsonify, Response
import requests
from PIL import Image, ExifTags
from io import BytesIO
import re
import time
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)

# ----- Basic Auth -----
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
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("WhoCallsMe", "https://whocallsme.com/Phone-Number.aspx/{p}"),
    ("800notes", "https://800notes.com/Phone.aspx/{p}"),
]

# ----- Helpers -----
def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\\D+", "", raw or "")
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
    import urllib.parse
    return f"https://www.google.com/search?q={urllib.parse.quote_plus(q)}"

# ----- Template -----
INDEX_HTML = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OSINT Scout - Web</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
  <nav class="navbar navbar-dark bg-dark mb-3">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">OSINT Scout</span>
      <span class="text-white-50">Public OSINT pivots (for lawful use)</span>
    </div>
  </nav>
  <div class="container">
    <form id="main-form">
      <div class="row">
        <div class="col-md-4">
          <h5>Inputs</h5>
          <div class="mb-2"><input class="form-control" id="name" placeholder="Full name"></div>
          <div class="mb-2"><input class="form-control" id="city" placeholder="City"></div>
          <div class="mb-2"><input class="form-control" id="state" placeholder="State"></div>
          <div class="mb-2"><input class="form-control" id="username" placeholder="Username/handle"></div>
          <div class="mb-2"><input class="form-control" id="email" placeholder="Email"></div>
          <div class="mb-2"><input class="form-control" id="phone" placeholder="Phone"></div>
          <div class="mb-2"><input class="form-control" id="domain" placeholder="Domain"></div>
          <div class="mb-2"><input class="form-control" id="ip" placeholder="IP"></div>
          <div class="mb-2 d-flex gap-2">
            <button type="button" id="build-pivots" class="btn btn-success btn-sm">Build Pivots</button>
            <button type="button" id="check-username" class="btn btn-primary btn-sm">Check Username (HTTP)</button>
            <button type="button" id="exif-upload-btn" class="btn btn-secondary btn-sm">Upload Image (EXIF)</button>
          </div>
          <div class="mb-2"><input type="file" id="imgfile" style="display:none"></div>
        </div>
        <div class="col-md-8">
          <h5>Results</h5>
          <div id="results" class="border rounded p-3" style="min-height:300px"></div>
        </div>
      </div>
    </form>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
  <script>
    const results = document.getElementById('results')
    document.getElementById('build-pivots').onclick = async () => {
      const payload = {
        name: document.getElementById('name').value.trim(),
        city: document.getElementById('city').value.trim(),
        state: document.getElementById('state').value.trim(),
        username: document.getElementById('username').value.trim(),
        email: document.getElementById('email').value.trim(),
        phone: document.getElementById('phone').value.trim(),
        domain: document.getElementById('domain').value.trim(),
        ip: document.getElementById('ip').value.trim(),
      }
      if(!Object.values(payload).some(v=>v)){ alert('Enter at least one field'); return }
      results.innerHTML = 'Building search pivots...'
      const r = await axios.post('/api/pivots', payload)
      let html = ''
      for(const section of r.data.sections){
        html += `<h6 class="mt-3">${section.title}</h6><ul>`
        for(const item of section.items){
          html += `<li><a href="${item.url}" target="_blank">${item.label}</a></li>`
        }
        html += '</ul>'
      }
      results.innerHTML = html
    }
  </script>
  </body>
</html>
'''

@app.route('/')
@require_basic_auth
def index():
    return render_template_string(INDEX_HTML)

@app.route('/api/pivots', methods=['POST'])
@require_basic_auth
def api_pivots():
    data = request.get_json() or {}
    sections = []

    def add_section(title, items):
        if items:
            sections.append({"title": title, "items": items})

    name = data.get('name', '').strip()
    if name:
        items = [{"label": "Google Search", "url": g(name)}]
        add_section("People", items)

    username = data.get('username', '').strip()
    if username:
        items = [{"label": s, "url": tmpl.format(u=username)} for s, tmpl in USERNAME_SITES]
        add_section("Username", items)

    email = data.get('email', '').strip()
    if email:
        q = f'"{email}"'
        items = [{"label": l, "url": t.format(q=q, e=email)} if "{q}" in t or "{e}" in t else {"label": l, "url": t} for l,t in EMAIL_LINKS]
        add_section("Email", items)

    phone = data.get('phone', '').strip()
    if phone:
        norm = normalize_phone(phone)
        items = [{"label": l, "url": t.format(q=phone, p=norm)} if "{q}" in t or "{p}" in t else {"label": l, "url": t} for l,t in PHONE_LINKS]
        add_section("Phone", items)

    domain = data.get('domain', '').strip()
    if domain:
        items = [{"label": l, "url": t.format(t=domain)} for l,t in DOMAIN_LINKS]
        add_section("Domain", items)

    ip = data.get('ip', '').strip()
    if ip:
        items = [{"label": l, "url": t.format(t=ip)} for l,t in IP_LINKS]
        add_section("IP", items)

    return jsonify({"sections": sections})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

