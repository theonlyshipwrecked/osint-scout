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
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("WhoCallsMe", "https://whocallsme.com/Phone-Number.aspx/{p}"),
    ("800notes", "https://800notes.com/Phone.aspx/{p}"),
]

# -----------------------------
# Google dorks for precise searches
# -----------------------------
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
}

# ----- Helpers -----
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
    # Build a Google search URL safely
    return f"https://www.google.com/search?q={urllib.parse.quote_plus(q)}"

# ----- HTML template (single-file UI) -----
INDEX_HTML = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OSINT Scout - Web</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { padding-bottom: 40px; }
      pre.exif { white-space: pre-wrap; }
    </style>
  </head>
  <body>
  <nav class="navbar navbar-dark bg-dark mb-3">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">OSINT Scout</span>
      <span class="text-white-50">Targeted OSINT pivots (for lawful use)</span>
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

    <hr>
    <div class="d-flex justify-content-between">
      <div>
        <button class="btn btn-outline-success" id="export-report">Export JSON Report</button>
      </div>
      <div class="text-muted">For lawful investigations only. Respect laws, privacy, and terms.</div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
  <script>
    const results = document.getElementById('results')

    // Build Pivots (works with ANY single field)
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
      results.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div> Building search pivots...'
      try{
        const r = await axios.post('/api/pivots', payload)
        renderPivotResults(r.data)
      }catch(e){ results.innerText = 'Error: ' + (e.message||e) }
    }

    function renderPivotResults(data){
      let html = ''
      for(const section of data.sections){
        html += `<h6 class="mt-3">${section.title}</h6><ul>`
        for(const item of section.items){
          html += `<li><a href="${item.url}" target="_blank" rel="noopener noreferrer">${item.label}</a></li>`
        }
        html += '</ul>'
      }
      if(!html) html = '<div class="text-muted">No pivots produced</div>'
      results.innerHTML = html
    }

    // Username HTTP check
    document.getElementById('check-username').onclick = async () => {
      const u = document.getElementById('username').value.trim();
      if(!u){alert('Enter a username');return}
      results.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div> Checking...'
      try{
        const r = await axios.post('/api/check_username', {username: u})
        renderUsernameResults(r.data)
      }catch(e){results.innerText = 'Error: '+(e.message||e)}
    }

    function renderUsernameResults(data){
      let html = '<h6>Username check</h6>'
      html += '<ul>'
      for(const it of data.results){
        html += `<li><strong>${it.site}</strong>: <a href='${it.url}' target='_blank' rel='noopener noreferrer'>${it.url}</a> — ${it.status || 'link'}`
        if(it.final_url && it.final_url!=it.url) html += ` → <small>${it.final_url}</small>`
        html += '</li>'
      }
      html += '</ul>'
      results.innerHTML = html
    }

    // EXIF upload
    document.getElementById('exif-upload-btn').onclick = () => document.getElementById('imgfile').click()
    document.getElementById('imgfile').onchange = async (e)=>{
      const f = e.target.files[0]
      if(!f) return
      const form = new FormData(); form.append('file', f)
      results.innerHTML = 'Reading image...'
      const r = await axios.post('/api/exif', form, {headers: {'Content-Type': 'multipart/form-data'}})
      let html = '<h6>EXIF</h6>'
      if(r.data.exif && Object.keys(r.data.exif).length){
        html += '<ul>'
        for(const k in r.data.exif){ html += `<li><strong>${k}</strong>: ${r.data.exif[k]}</li>` }
        html += '</ul>'
      } else html += '<div class="text-muted">No EXIF found</div>'
      results.innerHTML = html
    }

    // Export report
    document.getElementById('export-report').onclick = async ()=>{
      const payload = {
        name: document.getElementById('name').value,
        city: document.getElementById('city').value,
        state: document.getElementById('state').value,
        username: document.getElementById('username').value,
        email: document.getElementById('email').value,
        phone: document.getElementById('phone').value,
        domain: document.getElementById('domain').value,
        ip: document.getElementById('ip').value,
      }
      const r = await axios.post('/api/report', payload)
      const blob = new Blob([JSON.stringify(r.data, null, 2)], {type: 'application/json'})
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = 'osint_report.json'; a.click(); URL.revokeObjectURL(url)
    }
  </script>
  </body>
</html>
'''

# --------------------------
# Routes / API
# --------------------------
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

    # People (name + optional city/state)
    name = data.get('name', '').strip()
    city = data.get('city', '').strip()
    state = data.get('state', '').strip()
    if name:
        full = f'"{name}" {city} {state}'.strip()
        items = [
            {"label": "Google Search: " + full, "url": g(full)},
            {"label": "Social/Resume: " + full, "url": g(f'{full} site:facebook.com OR site:linkedin.com OR site:instagram.com')},
        ]
        add_section("People", items)

        # add google dorks for name
        dorks = []
        for pattern in GOOGLE_DORKS.get("name", []):
            q = pattern.format(name=name, city=city, state=state).strip()
            dorks.append({"label": q, "url": g(q)})
        add_section("Google dorks (Name)", dorks)

    # Username pivots
    username = data.get('username', '').strip()
    if username:
        items = [{"label": s, "url": tmpl.format(u=username)} for s, tmpl in USERNAME_SITES]
        add_section("Username profiles (links)", items)

        dorks = []
        for pattern in GOOGLE_DORKS.get("username", []):
            q = pattern.format(u=username)
            dorks.append({"label": q, "url": g(q)})
        add_section("Google dorks (Username)", dorks)

    # Email pivots
    email = data.get('email', '').strip()
    if email:
        q = f'"{email}"'
        items = []
        for label, tmpl in EMAIL_LINKS:
            if "{q}" in tmpl:
                url = tmpl.format(q=urllib.parse.quote_plus(q))
            elif "{e}" in tmpl:
                url = tmpl.format(e=urllib.parse.quote_plus(email))
            else:
                url = tmpl
            items.append({"label": label, "url": url})
        add_section("Email", items)

        dorks = []
        for pattern in GOOGLE_DORKS.get("email", []):
            q = pattern.format(email=email)
            dorks.append({"label": q, "url": g(q)})
        add_section("Google dorks (Email)", dorks)

    # Phone pivots
    phone = data.get('phone', '').strip()
    if phone:
        norm = normalize_phone(phone)
        items = []
        for label, tmpl in PHONE_LINKS:
            if "{q}" in tmpl:
                url = tmpl.format(q=urllib.parse.quote_plus(norm or phone))
            elif "{p}" in tmpl:
                url = tmpl.format(p=norm or phone)
            else:
                url = tmpl
            items.append({"label": label, "url": url})
        add_section("Phone", items)

        dorks = []
        for pattern in GOOGLE_DORKS.get("phone", []):
            q = pattern.format(phone=phone)
            dorks.append({"label": q, "url": g(q)})
        add_section("Google dorks (Phone)", dorks)

    # Domain pivots
    domain = data.get('domain', '').strip()
    if domain:
        items = [{"label": label, "url": tmpl.format(t=domain)} for label, tmpl in DOMAIN_LINKS]
        add_section("Domain", items)

        dorks = []
        for pattern in GOOGLE_DORKS.get("domain", []):
            q = pattern.format(domain=domain)
            dorks.append({"label": q, "url": g(q)})
        add_section("Google dorks (Domain)", dorks)

    # IP pivots
    ip = data.get('ip', '').strip()
    if ip:
        items = [{"label": label, "url": tmpl.format(t=ip)} for label, tmpl in IP_LINKS]
        add_section("IP", items)

        dorks = []
        for pattern in GOOGLE_DORKS.get("ip", []):
            q = pattern.format(ip=ip)
            dorks.append({"label": q, "url": g(q)})
        add_section("Google dorks (IP)", dorks)

    return jsonify({"sections": sections})

@app.route('/api/check_username', methods=['POST'])
@require_basic_auth
def api_check_username():
    data = request.get_json() or {}
    u = data.get('username', '').strip()
    if not u:
        return jsonify({'error': 'username required'}), 400
    results = []
    for site, tmpl in USERNAME_SITES:
        url = tmpl.format(u=u)
        status = 'link'
        final = ''
        info = http_check(url)
        if 'error' in info:
            status = 'error'
            final = info['error'][:200]
        else:
            status = f"HTTP {info.get('status_code')}"
            final = info.get('final_url')
        results.append({'site': site, 'url': url, 'status': status, 'final_url': final})
        time.sleep(NET_DELAY)
    return jsonify({'results': results})

@app.route('/api/exif', methods=['POST'])
@require_basic_auth
def api_exif():
    if 'file' not in request.files:
        return jsonify({'error': 'file missing'}), 400
    f = request.files['file']
    data = f.read()
    exif = exif_from_bytes(data)
    return jsonify({'exif': exif})

@app.route('/api/report', methods=['POST'])
@require_basic_auth
def api_report():
    payload = request.get_json() or {}
    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'inputs': payload,
        'notes': 'Exported from OSINT Scout - Flask web app',
    }
    return jsonify(report)

# Local dev
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

