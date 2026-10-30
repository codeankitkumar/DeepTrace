import os, subprocess, sys, time, urllib.request, json

os.environ["SECRET_KEY"] = "smoke-test-key"
os.environ["EVIDENCE_ENCRYPTION_KEY"] = "629N15khwM2Q9Abj2eZx0sY7wBjwVDM7bb5VmkpGMhs="
os.environ["SEED_ADMIN_PASSWORD"] = "AdminPass123!"

python = sys.executable
proc = subprocess.Popen([python, "-m", "uvicorn", "app.main:app", "--port", "8010"],
                        cwd=r"E:\Projectss\DeepTrace\backend",
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    base = "http://localhost:8010/api"
    # wait for health
    ok = False
    for _ in range(40):
        try:
            with urllib.request.urlopen(base + "/health", timeout=1) as r:
                print("HEALTH:", r.read().decode())
                ok = True
                break
        except Exception:
            time.sleep(0.5)
    if not ok:
        print("HEALTH_FAILED")
        sys.exit(1)

    req = urllib.request.Request(base + "/auth/login", data=json.dumps({
        "username": "admin", "password": "AdminPass123!"}).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        body = json.loads(r.read())
    print("LOGIN_OK token_len=", len(body["access_token"]), "role=", body["user"]["role"])

    headers = {"Authorization": "Bearer " + body["access_token"], "Content-Type": "application/json"}
    # create case
    req = urllib.request.Request(base + "/cases", data=json.dumps(
        {"name": "Smoke Case", "description": "live test"}).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req) as r:
        case = json.loads(r.read())
    print("CASE_ID=", case["id"])

    # dashboard overview
    req = urllib.request.Request(base + "/dashboard/overview", headers=headers)
    with urllib.request.urlopen(req) as r:
        print("OVERVIEW:", json.loads(r.read()))
    print("SMOKE_OK")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()