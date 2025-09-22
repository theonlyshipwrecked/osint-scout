# OSINT Scout — Flask web app (with Basic Auth)
# Deploy-ready for Render.com
#
# Quick local run:
#   pip install -r requirements.txt
#   python osint_scout_flask.py
# Then open http://localhost:5000
#
# Render deploy (gunicorn, $PORT binding) is handled by Procfile/render.yaml.
# Set env vars on Render:
#   APP_USER=<username>
#   APP_PASS=<password>

from flask import Flask, render_template_string, request, jsonify, abort, Response
import requests
from PIL import Image, ExifTags
from io import BytesIO
import re
import time
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)

# ----- Basic Auth (set APP_USER and APP_PASS env vars on Render) -----
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
    ("HaveIBeenPwned", "https://haveibeenpwned.com/"),
    ("Gravatar", "https://en.gravatar.com/site/check/{e}"),
]

PHONE_LINKS = [
    ("WhoCallsMe", "https://whocallsme.com/Phone-Number.aspx/{p}"),
]

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
        from PIL import ExifTags
        return {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    except Exception:
        return {}

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
          <div class="mb-2">
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
      <div class="text-muted">For lawful, internal use only.</div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
  <script>
    const results = document.getElementById('results')
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
        html += `<li><strong>${it.site}</strong>: <a href='${it.url}' target='_blank'>${it.url}</a> — ${it.status || 'link'}`
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

# ----- Routes -----
@app.route('/')
@require_basic_auth
def index():
    return render_template_string(INDEX_HTML)

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
        'notes': 'Exported from OSINT Scout — Flask web app',
    }
    return jsonify(report)

if __name__ == '__main__':
    # Local dev only (Render uses gunicorn/Procfile)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
