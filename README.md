# OSINT Scout — Flask Web App (Render.com ready)

## Files
- `osint_scout_flask.py` — Flask app (with Basic Auth)
- `requirements.txt` — Python deps
- `Procfile` — Start command for Render/Heroku
- `render.yaml` — Optional Render blueprint

## Run locally
```bash
python -m venv .venv
. .venv/Scripts/activate   # Windows PowerShell
pip install -r requirements.txt
python osint_scout_flask.py
# open http://localhost:5000
```

## Deploy to Render (GUI)
1. Put these files in a new GitHub repo.
2. On Render: New → Web Service → Connect repo
3. Build: `pip install -r requirements.txt`
4. Start: `gunicorn -b 0.0.0.0:$PORT osint_scout_flask:app`
5. Add env vars: `APP_USER`, `APP_PASS`
6. Open the public URL (browser will ask for username/password).
