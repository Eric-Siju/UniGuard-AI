import urllib.request

routes = [
    '/',
    '/threats',
    '/investigation',
    '/model',
    '/assets',
    '/hunt',
    '/cases',
    '/reports',
    '/settings',
    '/datasources',
    '/assets/index-CuRYcqaj.js',
    '/assets/index-BDDsADpJ.css'
]

base = "https://uniguard-ai-sih.vercel.app"
print(f"Testing Vercel deployment routes at {base}...")

all_ok = True
for r in routes:
    url = f"{base}{r}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "UniGuard-Deploy-Verifier/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            print(f"  [x] Route {r:15} -> Status: {status} ({content_type.split(';')[0]})")
    except Exception as e:
        print(f"  [!] Route {r:15} -> Error: {e}")
        all_ok = False

if all_ok:
    print("[SUCCESS] All 10 frontend SPA routes are properly routed and returning 200 OK!")
else:
    print("[WARN] Some routes did not return 200.")
