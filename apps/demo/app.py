"""Minimal independent demo upstreams. Replace with your applications."""
import os
from aiohttp import web, WSMsgType

ROLE = os.getenv("APP_ROLE", "web")
INSTANCE = os.getenv("INSTANCE", ROLE)

async def health(request):
    req_id = request.headers.get("X-Request-ID")
    data = {"status": "ok", "service": INSTANCE}
    if req_id:
        data["requestId"] = req_id
    headers = {"X-Request-ID": req_id} if req_id else {}
    return web.json_response(data, headers=headers)

async def index(request):
    req_id = request.headers.get("X-Request-ID")
    headers = {"X-Request-ID": req_id} if req_id else {}
    if ROLE == "web":
        return web.Response(
            text=("<!doctype html><html><head><meta charset='utf-8'>"
                  "<title>RouteKernel</title></head><body>"
                  "<h1>RouteKernel</h1><p>Gateway online.</p>"
                  "<p>Try <a href='/api/'>/api/</a> and WebSocket /ws/.</p>"
                  "</body></html>"),
            content_type="text/html",
            headers=headers,
        )
    data = {"service": ROLE, "instance": INSTANCE, "path": request.path}
    if req_id:
        data["requestId"] = req_id
    return web.json_response(data, headers=headers)

async def ws_handler(request):
    if ROLE != "realtime":
        raise web.HTTPNotFound()
    ws = web.WebSocketResponse(heartbeat=30, max_msg_size=1024 * 1024)
    await ws.prepare(request)
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                await ws.send_str(f"echo:{msg.data}")
            elif msg.type == WSMsgType.BINARY:
                await ws.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                break
    except (ConnectionResetError, RuntimeError):
        pass
    finally:
        if not ws.closed:
            await ws.close()
    return ws

def create_app():
    app = web.Application(client_max_size=10 * 1024 * 1024)
    app.router.add_get("/health", health)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/ws/", ws_handler)
    app.router.add_get("/{tail:.*}", index)
    return app

if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8000)
