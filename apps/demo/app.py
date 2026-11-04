"""Minimal independent demo upstreams. Replace with your applications."""
import os
from aiohttp import web, WSMsgType

ROLE = os.getenv("APP_ROLE", "web")
INSTANCE = os.getenv("INSTANCE", ROLE)

async def health(request):
    return web.json_response({"status": "ok", "service": INSTANCE})

async def index(request):
    if ROLE == "web":
        return web.Response(
            text=("<!doctype html><html><head><meta charset='utf-8'>"
                  "<title>RouteKernel</title></head><body>"
                  "<h1>RouteKernel</h1><p>Gateway online.</p>"
                  "<p>Try <a href='/api/'>/api/</a> and WebSocket /ws/.</p>"
                  "</body></html>"),
            content_type="text/html",
        )
    return web.json_response({"service": ROLE, "instance": INSTANCE, "path": request.path})

async def ws_handler(request):
    if ROLE != "realtime":
        raise web.HTTPNotFound()
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            await ws.send_str(f"echo:{msg.data}")
        elif msg.type == WSMsgType.BINARY:
            await ws.send_bytes(msg.data)
        elif msg.type == WSMsgType.ERROR:
            break
    return ws

def create_app():
    app = web.Application(client_max_size=10 * 1024 * 1024)
    app.router.add_get("/health", health)
    app.router.add_get("/ws/", ws_handler)
    app.router.add_get("/{tail:.*}", index)
    return app

if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8000)
