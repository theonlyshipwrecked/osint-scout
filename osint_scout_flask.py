# osint_scout_flask.py
# OSINT Scout — Flask web app (v3.3)
# - Family Tree pivots (Ancestry, Find a Grave, Whitepages, FamilyTreeNow)
# - Removed per request: MyHeritage, Newspapers.com, FamilySearch, TruePeopleSearch, Spokeo
# - Google dorks (name, username, email, phone, domain, IP, family/obits) updated to remove FamilySearch/Newspapers dorks and add FamilyTreeNow dork
# - IP pivots include CentralOps Domain Dossier
# - Username HTTP check, Image EXIF (JPEG + HEIC), JSON report export
# - Optional Basic Auth: set APP_USER and APP_PASS in your environment (e.g., on Render)

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

# Enable HEIC/HEIF via pillow-heif if available
try:
    import pillow_heif  # type: ignore
    pillow_heif.register_heif_opener()
except Exception:
    pass

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

# ---------- Helpers ----------
def _q(s: str) -> str:
    return urllib.parse.quote_plus(s or "")

def _dash_name(full_name: str) -> str:
    return re.sub(r"\s+", "-", (full_name or "").strip())

def _split_first_last(name: str, surname: str):
    """Best-effort split for FamilyTreeNow URL parameters."""
    first = ""
    last = surname.strip() if surname else ""
    toks = [t for t in (name or "").strip().split() if t]
    if toks:
        first = toks[0]
        if not last and len(toks) >= 2:
            last = toks[-1]
    return first, last

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

def _decode_exif_value(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", "ignore")
        except Exception:
            return repr(v)
    return v

def _gps_to_decimal(gps):
    def _to_deg(val):
        d = val[0][0] / val[0][1]
        m = val[1][0] / val[1][1]
        s = val[2][0] / val[2][1]
        return d + (m / 60.0) + (s / 3600.0)
    lat = lon = None
    lat_ref = gps.get("GPSLatitudeRef")
    lon_ref = gps.get("GPSLongitudeRef")
    lat_raw = gps.get("GPSLatitude")
    lon_raw = gps.get("GPSLongitude")
    if lat_raw and lon_raw:
        try:
            lat = _to_deg(lat_raw)
            lon = _to_deg(lon_raw)
            if lat_ref in ("S", b"S"):
                lat = -lat
            if lon_ref in ("W", b"W"):
                lon = -lon
        except Exception:
            pass
    return lat, lon

def exif_from_bytes(data: bytes):
    img = Image.open(BytesIO(data))
    meta = {
        "format": img.format,
        "size": f"{img.size[0]}x{img.size[1]}",
        "mode": img.mode,
    }
    exif_out = {}
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    if exif:
        for k, v in exif.items():
            tag = ExifTags.TAGS.get(k, k)
            exif_out[tag] = _decode_exif_value(v)
        gps_raw = exif.get(34853)  # GPSInfo
        if gps_raw:
            gps_named = {}
            for gk, gv in gps_raw.items():
                gps_named[ExifTags.GPSTAGS.get(gk, gk)] = gv
            exif_out["GPSInfo"] = gps_named
            lat, lon = _gps_to_decimal(gps_named)
            if lat is not None and lon is not None:
                exif_out["GPSDecimal"] = {"lat": lat, "lon": lon}
    return meta, exif_out

def g(q: str) -> str:
    return f"https://www.google.com/search?q={urllib.parse.quote_plus(q)}"

# ---------- Family tree / genealogy pivots ----------
FAMILY_SITES = [
    ("Ancestry (search)", "https://www.ancestry.com/search/?name={name_q}&birth={by}&death={dy}&keywords={kw}"),
    ("Find a Grave (search)", "https://www.findagrave.com/memorial/search?firstname={name_q}&lastname={surname_q}&birthyear={by}&deathyear={dy}"),
    ("FamilyTreeNow (people)", "https://www.familytreenow.com/search/people?first={first}&last={last}&citystatezip={city}%20{state}"),
    ("Whitepages*", "https://www.whitepages.com/name/{name_dash}/{state}"),
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
        # Removed site:newspapers.com and site:familysearch.org per request
        '"{name}" {surname} {city} {state} obituary',
        '"{name}" {surname} obituary "{relative}"',
        '"{name}" {surname} "mother" OR "father" OR "brother" OR "sister" {city} {state}',
        '"{name}" {surname} marriage license {state}',
        '"{name}" {surname} site:findagrave.com',
        '"{name}" {surname} site:familytreenow.com',
        '"{name}" {surname} genealogy {city} {state}',
    ],
}

# ---------- HTML (full template) ----------
INDEX_HTML = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OSINT Scout - Web</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body{padding-bottom:40px} pre.exif{white-space:pre-wrap}</style>
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
          <div class="mb-2"><input class="form-control" id="name" placeholder="Full name (e.g., Jane Ann Doe)"></div>
          <div class="mb-2"><input class="form-control" id="surname" placeholder="Surname / Maiden (optional)"></div>
          <div class="mb-2"><input class="form-control" id="city" placeholder="City"></div>
          <div class="mb-2"><input class="form-control" id="state" placeholder="State"></div>
          <div class="mb-2 d-flex gap-2">
            <input class="form-control" id="birth_year" placeholder="Birth Year (YYYY)">
            <input class="form-control" id="death_year" placeholder="Death Year (YYYY)">
          </div>
          <div class="mb-2"><input class="form-control" id="relative" placeholder="Relative's name (optional)"></div>

          <hr class="my-3">

          <div class="mb-2"><input class="form-control" id="username" placeholder="Username/handle"></div>
          <div class="mb-2"><input class="form-control" id="email" placeholder="Email"></div>
          <div class="mb-2"><input class="form-control" id="phone" placeholder="Phone"></div>
          <div class="mb-2"><input class="form-control" id="domain" placeholder="Domain"></div>
          <div class="mb-2"><input class="form-control" id="ip" placeholder="IP"></div>

          <div class="mb-2 d-flex gap-2 flex-wrap">
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
      <div><button class="btn btn-outline-success" id="export-report">Export JSON Report</button></div>
      <div class="text-muted">Use lawfully and respect site terms.</div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
  <script>
    const results = document.getElementById('results');

    document.getElementById('build-pivots').onclick = async () => {
      const payload = {
        name: document.getElementById('name').value.trim(),
        surname: document.getElementById('surname').value.trim(),
        city: document.getElementById('city').value.trim(),
        state: document.getElementById('state').value.trim(),
        birth_year: document.getElementById('birth_year').value.trim(),
        death_year: document.getElementById('death_year').value.trim(),
        relative: document.getElementById('relative').value.trim(),

        username: document.getElementById('username').value.trim(),
        email: document.getElementById('email').value.trim(),
        phone: document.getElementById('phone').value.trim(),
        domain: document.getElementById('domain').value.trim(),
        ip: document.getElementById('ip').value.trim(),
      };
      if(!Object.values(payload).some(v=>v)){ alert('Enter at least one field'); return }
      results.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div> Building search pivots...';
      try{
        const r = await axios.post('/api/pivots', payload);
        let html = '';
        for(const section of r.data.sections){
          html += `<h6 class="mt-3">${section.title}</h6><ul>`;
          for(const item of section.items){
            html += `<li><a href="${item.url}" target="_blank" rel="noopener noreferrer">${item.label}</a></li>`;
          }
          html += '</ul>';
        }
        if(!html) html = '<div class="text-muted">No pivots produced</div>';
        results.innerHTML = html;
      }catch(e){ results.innerText = 'Error: ' + (e.message||e); }
    };

    document.getElementById('check-username').onclick = async () => {
      const u = document.getElementById('username').value.trim();
      if(!u){alert('Enter a username');return}
      results.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div> Checking...'
      try{
        const r = await axios.post('/api/check_username', {username: u});
        let html = '<h6>Username check</h6><ul>';
        for(const it of r.data.results){
          html += `<li><strong>${it.site}</strong>: <a href='${it.url}' target='_blank' rel='noopener noreferrer'>${it.url}</a> — ${it.status || 'link'}`;
          if(it.final_url && it.final_url!=it.url) html += ` → <small>${it.final_url}</small>`;
          html += '</li>';
        }
        html += '</ul>';
        results.innerHTML = html;
      }catch(e){ results.innerText = 'Error: '+(e.message||e); }
    };

    // EXIF upload (better errors + meta)
    document.getElementById('exif-upload-btn').onclick = () => document.getElementById('imgfile').click()
    document.getElementById('imgfile').onchange = async (e)=>{
      const f = e.target.files[0]
      if(!f) return
      const form = new FormData(); form.append('file', f)
      results.innerHTML = 'Reading image...'
      try{
        const r = await axios.post('/api/exif', form, {headers: {'Content-Type': 'multipart/form-data'}})
        let html = '<h6>EXIF</h6>'

        if(r.data.error){
          html += `<div class="text-danger">Error: ${r.data.error}</div>`
          results.innerHTML = html
          return
        }

        if(r.data.meta){
          const m = r.data.meta
          html += `<div class="mb-2"><strong>Format:</strong> ${m.format || '-'} &nbsp; <strong>Size:</strong> ${m.size || '-'} &nbsp; <strong>Mode:</strong> ${m.mode || '-'}</div>`
        }

        if(r.data.exif && Object.keys(r.data.exif).length){
          html += '<ul>'
          for(const k in r.data.exif){
            const v = r.data.exif[k]
            if(k === 'GPSDecimal' && v && v.lat !== undefined){
              html += `<li><strong>GPS (decimal)</strong>: ${v.lat}, ${v.lon}</li>`
            } else if (typeof v === 'object'){
              html += `<li><strong>${k}</strong>: <pre class="exif">${JSON.stringify(v, null, 2)}</pre></li>`
            } else {
              html += `<li><strong>${k}</strong>: ${v}</li>`
            }
          }
          html += '</ul>'
        } else {
          html += '<div class="text-muted">No EXIF found. (Common for PNGs, screenshots, and images saved from social media.) Try an original photo (JPEG/HEIC) straight from the device.</div>'
        }
        results.innerHTML = html
      }catch(err){
        results.innerHTML = `<div class="text-danger">Error reading EXIF: ${err?.response?.data?.error || err.message}</div>`
      }
    }

    document.getElementById('export-report').onclick = async ()=>{
      const payload = {
        name: document.getElementById('name').value,
        surname: document.getElementById('surname').value,
        city: document.getElementById('city').value,
        state: document.getElementById('state').value,
        birth_year: document.getElementById('birth_year').value,
        death_year: document.getElementById('death_year').value,
        relative: document.getElementById('relative').value,

        username: document.getElementById('username').value,
        email: document.getElementById('email').value,
        phone: document.getElementById('phone').value,
        domain: document.getElementById('domain').value,
        ip: document.getElementById('ip').value,
      };
      const r = await axios.post('/api/report', payload);
      const blob = new Blob([JSON.stringify(r.data, null, 2)], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'osint_report.json'; a.click(); URL.revokeObjectURL(url);
    };
  </script>
  </body>
</html>
'''

# ---------- Routes ----------
@app.route('/')
@require_basic_auth
def index():
    return render_template_string(INDEX_HTML)

@app.route('/api/pivots', methods=['POST'])
@require_basic_auth
def api_pivots():
    d = request.get_json() or {}
    sections = []

    def add_section(title, items):
        if items:
            sections.append({"title": title, "items": items})

    # --- Family Tree pivots (if name or surname exists) ---
    name = (d.get('name') or '').strip()
    surname = (d.get('surname') or '').strip()
    city = (d.get('city') or '').strip()
    state = (d.get('state') or '').strip()
    by = (d.get('birth_year') or '').strip()
    dy = (d.get('death_year') or '').strip()
    relative = (d.get('relative') or '').strip()

    if name or surname:
        name_q = _q(name)
        surname_q = _q(surname)
        kw = _q(" ".join(x for x in [city, state, relative] if x))
        name_dash = _dash_name(name or "")
        first, last = _split_first_last(name, surname)
        items = []
        for label, tmpl in FAMILY_SITES:
            url = tmpl.format(
                name_q=name_q, surname_q=surname_q, by=_q(by), dy=_q(dy),
                kw=kw, city=_q(city), state=_q(state), name_dash=name_dash,
                first=_q(first), last=_q(last)
            )
            items.append({"label": label, "url": url})
        add_section("Family Tree / Genealogy", items)

        # Family-focused Google dorks (updated to include FamilyTreeNow; removed FS/Newspapers)
        dorks = []
        for pattern in GOOGLE_DORKS.get("family", []):
            q = pattern.format(name=name, surname=surname, city=city, state=state, relative=relative).strip()
            dorks.append({"label": q, "url": g(q)})
        add_section("Google dorks (Family/Obits)", dorks)

    # --- People (generic) ---
    if name:
        full = f'"{name}" {city} {state}'.strip()
        items = [
            {"label": "Google Search: " + full, "url": g(full)},
            {"label": "Social/Resume: " + full, "url": g(f'{full} site:facebook.com OR site:linkedin.com OR site:instagram.com')},
        ]
        add_section("People", items)
        dorks = [{"label": (q := p.format(name=name, city=city, state=state)), "url": g(q)} for p in GOOGLE_DORKS["name"]]
        add_section("Google dorks (Name)", dorks)

    # --- Username ---
    username = (d.get('username') or '').strip()
    if username:
        items = [{"label": s, "url": tmpl.format(u=username)} for s, tmpl in USERNAME_SITES]
        add_section("Username profiles (links)", items)
        dorks = [{"label": (q := p.format(u=username)), "url": g(q)} for p in GOOGLE_DORKS["username"]]
        add_section("Google dorks (Username)", dorks)

    # --- Email ---
    email = (d.get('email') or '').strip()
    if email:
        q_email = f'"{email}"'
        items = []
        for label, tmpl in EMAIL_LINKS:
            if "{q}" in tmpl:
                url = tmpl.format(q=urllib.parse.quote_plus(q_email))
            elif "{e}" in tmpl:
                url = tmpl.format(e=urllib.parse.quote_plus(email))
            else:
                url = tmpl
            items.append({"label": label, "url": url})
        add_section("Email", items)
        dorks = [{"label": (q := p.format(email=email)), "url": g(q)} for p in GOOGLE_DORKS["email"]]
        add_section("Google dorks (Email)", dorks)

    # --- Phone ---
    phone = (d.get('phone') or '').strip()
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
        dorks = [{"label": (q := p.format(phone=phone)), "url": g(q)} for p in GOOGLE_DORKS["phone"]]
        add_section("Google dorks (Phone)", dorks)

    # --- Domain ---
    domain = (d.get('domain') or '').strip()
    if domain:
        items = [{"label": label, "url": tmpl.format(t=domain)} for label, tmpl in DOMAIN_LINKS]
        add_section("Domain", items)
        dorks = [{"label": (q := p.format(domain=domain)), "url": g(q)} for p in GOOGLE_DORKS["domain"]]
        add_section("Google dorks (Domain)", dorks)

    # --- IP ---
    ip = (d.get('ip') or '').strip()
    if ip:
        items = [{"label": label, "url": tmpl.format(t=ip)} for label, tmpl in IP_LINKS]
        add_section("IP", items)
        dorks = [{"label": (q := p.format(ip=ip)), "url": g(q)} for p in GOOGLE_DORKS["ip"]]
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
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'file missing'}), 400
        f = request.files['file']
        data = f.read()
        if not data:
            return jsonify({'error': 'empty file'}), 400
        meta, exif = exif_from_bytes(data)
        return jsonify({'meta': meta, 'exif': exif})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
