"""
AeroNMS - Network Management System v1.3
Routes: dashboard, devices, monitor, SNMP, backup, alerts, detail, topology
"""

from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime
import os, io, asyncio
from concurrent.futures import ThreadPoolExecutor

_ping_executor = ThreadPoolExecutor(max_workers=30)

from database import SessionLocal, engine, Base
import models, monitor, crud, wazuh

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AeroNMS", version="1.3.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

VALID_USERS    = {"admin": "aero2024", "noc": "buddha@noc"}
SESSION_COOKIE = "aeronms_session"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def is_authenticated(request: Request) -> bool:
    return request.cookies.get(SESSION_COOKIE) == "authenticated"

# ─── Auth ─────────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if VALID_USERS.get(username) == password:
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(SESSION_COOKIE, "authenticated", httponly=True, max_age=86400)
        return response
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response

# ─── Dashboard ────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    devices = crud.get_all_devices(db)
    total   = len(devices)
    up      = sum(1 for d in devices if d.status == "UP")
    down    = sum(1 for d in devices if d.status == "DOWN")
    unknown = total - up - down
    alerts  = []
    if os.path.exists("logs/alerts.log"):
        with open("logs/alerts.log") as f:
            alerts = [l.strip() for l in f.readlines()[-10:] if l.strip()]
            alerts.reverse()
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "devices": devices,
        "total": total, "up": up, "down": down, "unknown": unknown,
        "alerts": alerts, "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

# ─── Devices ──────────────────────────────────────────────────────────────────
@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, search: str = "", db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    devices = crud.search_devices(db, search)
    return templates.TemplateResponse("devices.html", {
        "request": request, "devices": devices, "search": search
    })

@app.get("/devices/add", response_class=HTMLResponse)
async def add_device_page(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    all_devices = crud.get_all_devices(db)
    # Collect unique existing locations from DB for datalist suggestions
    existing_locations = sorted(set(d.location for d in all_devices if d.location))
    return templates.TemplateResponse("device_form.html", {
        "request": request, "device": None, "action": "Add",
        "all_devices": all_devices, "existing_locations": existing_locations
    })

@app.post("/devices/add")
async def add_device(
    request: Request,
    hostname: str = Form(...), ip_address: str = Form(...),
    device_type: str = Form(...), location: str = Form(...),
    description: str = Form(""), notes: str = Form(""),
    parent_id: str = Form(""),
    db: Session = Depends(get_db)
):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    pid = int(parent_id) if parent_id and parent_id.isdigit() else None
    crud.create_device(db, hostname, ip_address, device_type, location, description, notes, pid)
    return RedirectResponse("/devices", status_code=302)

@app.get("/devices/edit/{device_id}", response_class=HTMLResponse)
async def edit_device_page(request: Request, device_id: int, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    device = crud.get_device(db, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    all_devices = [d for d in crud.get_all_devices(db) if d.id != device_id]
    existing_locations = sorted(set(d.location for d in crud.get_all_devices(db) if d.location))
    return templates.TemplateResponse("device_form.html", {
        "request": request, "device": device, "action": "Edit",
        "all_devices": all_devices, "existing_locations": existing_locations
    })

@app.post("/devices/edit/{device_id}")
async def edit_device(
    request: Request, device_id: int,
    hostname: str = Form(...), ip_address: str = Form(...),
    device_type: str = Form(...), location: str = Form(...),
    description: str = Form(""), notes: str = Form(""),
    parent_id: str = Form(""),
    db: Session = Depends(get_db)
):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    pid = int(parent_id) if parent_id and parent_id.isdigit() else None
    crud.update_device(db, device_id, hostname, ip_address, device_type, location, description, notes, pid)
    return RedirectResponse("/devices", status_code=302)

@app.post("/devices/delete/{device_id}")
async def delete_device(request: Request, device_id: int, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    crud.delete_device(db, device_id)
    return RedirectResponse("/devices", status_code=302)

@app.get("/devices/export/csv")
async def export_csv(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    devices  = crud.get_all_devices(db)
    csv_data = monitor.export_devices_csv(devices)
    fname    = f"aeronms_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(io.StringIO(csv_data), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={fname}"})

# ─── Device Detail ─────────────────────────────────────────────────────────────
@app.get("/devices/detail/{device_id}", response_class=HTMLResponse)
async def device_detail(request: Request, device_id: int, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    device = crud.get_device(db, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    history    = crud.get_ping_history(db, device_id, limit=60)
    uptime_24h = crud.get_uptime_percent(db, device_id, hours=24)
    uptime_7d  = crud.get_uptime_percent(db, device_id, hours=168)
    avg_lat    = crud.get_avg_latency(db, device_id, hours=24)
    parent     = crud.get_device(db, device.parent_id) if device.parent_id else None
    children   = db.query(models.Device).filter(models.Device.parent_id == device_id).all()
    # SNMP loaded async by JS after page renders — no blocking here
    return templates.TemplateResponse("device_detail.html", {
        "request": request, "device": device, "history": list(reversed(history)),
        "uptime_24h": uptime_24h, "uptime_7d": uptime_7d,
        "avg_lat": avg_lat, "parent": parent, "children": children,
    })

# ─── Monitor ──────────────────────────────────────────────────────────────────
@app.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    devices = crud.get_all_devices(db)
    return templates.TemplateResponse("monitor.html", {"request": request, "devices": devices})

@app.get("/api/monitor/ping/{device_id}")
async def ping_device(request: Request, device_id: int, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    device = crud.get_device(db, device_id)
    if not device:
        return JSONResponse({"error": "Not found"}, status_code=404)
    result = monitor.ping_host(device.ip_address)
    crud.update_device_status(db, device_id, result["status"], result.get("latency_ms"))
    if result["status"] == "DOWN":
        monitor.log_alert(device.hostname, device.ip_address, device.location)
        monitor.send_email_alert(device.hostname, device.ip_address, device.location)
    return JSONResponse({
        "id": device.id, "hostname": device.hostname, "ip": device.ip_address,
        "status": result["status"], "latency_ms": result.get("latency_ms"),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })

@app.get("/api/monitor/all")
async def ping_all(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    devices = crud.get_all_devices(db)
    loop = asyncio.get_event_loop()

    async def ping_one(device):
        result = await loop.run_in_executor(_ping_executor, monitor.ping_host, device.ip_address)
        crud.update_device_status(db, device.id, result["status"], result.get("latency_ms"))
        if result["status"] == "DOWN":
            monitor.log_alert(device.hostname, device.ip_address, device.location)
            monitor.send_email_alert(device.hostname, device.ip_address, device.location)
        return {
            "id": device.id, "hostname": device.hostname, "ip": device.ip_address,
            "location": device.location, "device_type": device.device_type,
            "status": result["status"], "latency_ms": result.get("latency_ms"),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }

    results = await asyncio.gather(*[ping_one(d) for d in devices])
    return JSONResponse(list(results))


@app.get("/api/monitor/stream")
async def ping_stream(request: Request, db: Session = Depends(get_db)):
    """
    Server-Sent Events endpoint — streams each ping result as it completes.
    Frontend receives results one-by-one without blocking navigation.
    """
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    devices = crud.get_all_devices(db)
    loop    = asyncio.get_event_loop()
    queue   = asyncio.Queue()

    async def ping_one(device):
        result = await loop.run_in_executor(_ping_executor, monitor.ping_host, device.ip_address)
        crud.update_device_status(db, device.id, result["status"], result.get("latency_ms"))
        if result["status"] == "DOWN":
            monitor.log_alert(device.hostname, device.ip_address, device.location)
            monitor.send_email_alert(device.hostname, device.ip_address, device.location)
        await queue.put({
            "id": device.id, "hostname": device.hostname, "ip": device.ip_address,
            "location": device.location, "device_type": device.device_type,
            "status": result["status"], "latency_ms": result.get("latency_ms"),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        })

    async def event_generator():
        import json
        # Fire all pings concurrently
        tasks = [asyncio.create_task(ping_one(d)) for d in devices]
        total = len(devices)
        done  = 0
        yield f"data: {json.dumps({'type':'start','total':total})}\n\n"
        while done < total:
            result = await queue.get()
            done  += 1
            yield f"data: {json.dumps({'type':'result','done':done,'total':total,**result})}\n\n"
        yield f"data: {json.dumps({'type':'done','total':total})}\n\n"
        await asyncio.gather(*tasks, return_exceptions=True)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )

# ─── Ping History API ──────────────────────────────────────────────────────────
@app.get("/api/device/{device_id}/history")
async def device_history(request: Request, device_id: int, limit: int = 60, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    history = crud.get_ping_history(db, device_id, limit=limit)
    return JSONResponse([{
        "status": h.status,
        "latency_ms": h.latency_ms,
        "checked_at": h.checked_at.strftime("%H:%M:%S") if h.checked_at else "",
    } for h in reversed(history)])

# ─── Uptime API ────────────────────────────────────────────────────────────────
@app.get("/api/device/{device_id}/uptime")
async def device_uptime(request: Request, device_id: int, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse({
        "uptime_24h": crud.get_uptime_percent(db, device_id, 24),
        "uptime_7d":  crud.get_uptime_percent(db, device_id, 168),
        "avg_lat_24h": crud.get_avg_latency(db, device_id, 24),
    })

# ─── Topology API ─────────────────────────────────────────────────────────────
@app.get("/topology", response_class=HTMLResponse)
async def topology_page(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    devices = crud.get_all_devices(db)
    return templates.TemplateResponse("topology.html", {"request": request, "devices": devices})

@app.get("/api/topology")
async def topology_data(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    devices = crud.get_all_devices(db)
    nodes = [{
        "id": d.id, "label": d.hostname, "ip": d.ip_address,
        "type": d.device_type, "location": d.location,
        "status": d.status, "latency_ms": d.latency_ms,
        "parent_id": d.parent_id,
    } for d in devices]
    edges = [{"from": d.parent_id, "to": d.id}
             for d in devices if d.parent_id]
    return JSONResponse({"nodes": nodes, "edges": edges})

# ─── SNMP ─────────────────────────────────────────────────────────────────────
@app.get("/snmp", response_class=HTMLResponse)
async def snmp_page(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    devices = crud.get_all_devices(db)
    return templates.TemplateResponse("snmp.html", {"request": request, "devices": devices})

@app.get("/api/snmp/{device_id}")
async def snmp_poll_device(request: Request, device_id: int,
                            community: str = "public", version: str = "2c",
                            db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    device = crud.get_device(db, device_id)
    if not device:
        return JSONResponse({"error": "Not found"}, status_code=404)
    result = monitor.snmp_poll(device.ip_address, community, version)
    result.update({"hostname": device.hostname, "device_type": device.device_type, "location": device.location})
    return JSONResponse(result)

# ─── Backup ───────────────────────────────────────────────────────────────────
@app.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    devices = crud.get_all_devices(db)
    backups = []
    if os.path.exists("backups"):
        for f in sorted(os.listdir("backups"), reverse=True):
            if f.endswith(".txt"):
                path = os.path.join("backups", f)
                mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
                backups.append({"name": f, "size": os.path.getsize(path), "modified": mtime})
    return templates.TemplateResponse("backup.html", {
        "request": request, "devices": devices, "backups": backups[:20]
    })

@app.post("/api/backup/{device_id}")
async def backup_device(request: Request, device_id: int, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    device = crud.get_device(db, device_id)
    if not device:
        return JSONResponse({"error": "Not found"}, status_code=404)
    filename = monitor.create_backup(device)
    return JSONResponse({"success": True, "filename": filename, "device": device.hostname})

@app.post("/api/backup/all")
async def backup_all(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    devices = crud.get_all_devices(db)
    files = [monitor.create_backup(d) for d in devices]
    return JSONResponse({"success": True, "count": len(files), "files": files})

# ─── Email Alerts ─────────────────────────────────────────────────────────────
@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    cfg = monitor.load_email_config()
    return templates.TemplateResponse("alerts.html", {"request": request, "cfg": cfg})

@app.post("/api/alerts/config")
async def save_alert_config(
    request: Request,
    smtp_host: str = Form(...), smtp_port: str = Form(...),
    smtp_user: str = Form(...), smtp_pass: str = Form(...),
    from_addr: str = Form(...), to_addrs: str = Form(...),
    enabled: str = Form("off"),
):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    cfg = {
        "smtp_host": smtp_host, "smtp_port": int(smtp_port),
        "smtp_user": smtp_user, "smtp_pass": smtp_pass,
        "from_addr": from_addr,
        "to_addrs":  [e.strip() for e in to_addrs.split(",") if e.strip()],
        "enabled":   enabled == "on",
    }
    monitor.save_email_config(cfg)
    return JSONResponse({"success": True})

@app.post("/api/alerts/test")
async def test_alert(
    request: Request,
    smtp_host: str = Form(...), smtp_port: str = Form(...),
    smtp_user: str = Form(...), smtp_pass: str = Form(...),
    from_addr: str = Form(...), to_addrs: str = Form(...),
):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    cfg = {
        "smtp_host": smtp_host, "smtp_port": int(smtp_port),
        "smtp_user": smtp_user, "smtp_pass": smtp_pass,
        "from_addr": from_addr,
        "to_addrs":  [e.strip() for e in to_addrs.split(",") if e.strip()],
        "enabled":   True,
    }
    result = monitor.test_email(cfg)
    return JSONResponse(result)

@app.get("/api/alerts/log")
async def get_alerts_log(request: Request):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    alerts = []
    if os.path.exists("logs/alerts.log"):
        with open("logs/alerts.log") as f:
            alerts = [l.strip() for l in f.readlines()[-30:] if l.strip()]
            alerts.reverse()
    return JSONResponse({"alerts": alerts})

# ─── Wazuh Security Routes ────────────────────────────────────────────────────
@app.get("/security", response_class=HTMLResponse)
async def security_page(request: Request, db: Session = Depends(get_db)):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    cfg = wazuh.load_config()
    return templates.TemplateResponse("security.html", {
        "request": request, "cfg": cfg
    })

@app.get("/api/wazuh/alerts")
async def wazuh_alerts(request: Request, limit: int = 50):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = wazuh.get_alerts(limit)
    # Enrich with severity label and color
    for a in result["alerts"]:
        a["severity"]       = wazuh.severity_label(a["level"])
        a["severity_color"] = wazuh.severity_color(a["level"])
    return JSONResponse(result)

@app.get("/api/wazuh/agents")
async def wazuh_agents(request: Request):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse(wazuh.get_agents())

@app.get("/api/wazuh/summary")
async def wazuh_summary(request: Request):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse(wazuh.get_summary())

@app.post("/api/wazuh/config")
async def save_wazuh_config(
    request: Request,
    host:     str = Form(...),
    port:     str = Form("55000"),
    username: str = Form("wazuh-wui"),
    password: str = Form(...),
    enabled:  str = Form("off"),
):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    cfg = {
        "host":      host,
        "port":      int(port),
        "username":  username,
        "password":  password,
        "enabled":   enabled == "on",
        "verify_ssl": False,
    }
    wazuh.save_config(cfg)
    return JSONResponse({"success": True})

@app.post("/api/wazuh/test")
async def test_wazuh(
    request: Request,
    host:     str = Form(...),
    port:     str = Form("55000"),
    username: str = Form("wazuh-wui"),
    password: str = Form(...),
):
    if not is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    cfg = {
        "host": host, "port": int(port),
        "username": username, "password": password,
        "verify_ssl": False, "enabled": True,
    }
    return JSONResponse(wazuh.test_connection(cfg))
