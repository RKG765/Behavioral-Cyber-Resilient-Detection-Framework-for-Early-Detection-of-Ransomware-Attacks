# Project website

Static landing + download page for Telltale (no build step). Designed with the
`website-design-dark` skill: dark base, one green accent used only on CTAs, active nav, hover/focus
and the headline metric; Archivo Expanded / IBM Plex Sans / IBM Plex Mono; 60-30-10 color system.

## Preview

```bash
python -m http.server 8765 --bind 127.0.0.1 --directory site
```

## Publish (GitHub Pages)

Repository **Settings → Pages → Deploy from a branch → `main` / `/site`**, or copy the folder
to any static host (Netlify, Cloudflare Pages).

## Hook up the download

Edit [`config.js`](config.js). When a release has the installer attached, set `download` to:

```
https://github.com/<you>/<repo>/releases/latest/download/Telltale-Setup.exe
```

Until then the Download buttons open the releases page. Publish the SHA-256 of each installer in
its release notes.

## Dashboard

The dashboard (`web_app.py`) runs on each user's own machine at `http://127.0.0.1:5050/` after
install. It reads the local agent and has no authentication, so it is not hosted on this site.
The page shows a preview mock: replace `.mock` in `index.html` with a real screenshot when you
have one.
