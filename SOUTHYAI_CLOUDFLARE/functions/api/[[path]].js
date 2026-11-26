import handler, { setEnv } from "../../src/app.js";

// Cloudflare Pages Function: every /api/* request lands here and is handed to the app.
export async function onRequest({ request, env }) {
  setEnv(env);
  const url = new URL(request.url);
  const headers = Object.fromEntries(request.headers);
  headers.host = url.host;
  // <audio> tags can't send headers, so admin playback passes the session as ?t=
  if (url.pathname === "/api/admin/audio" && url.searchParams.get("t") && !headers.authorization)
    headers.authorization = "Bearer " + url.searchParams.get("t");
  const req = { method: request.method, url: url.pathname + url.search, headers, request };
  if ((headers["content-type"] || "").includes("application/json"))
    req.body = await request.json().catch(() => ({}));
  const res = {
    _s: 200, _h: new Headers(), _b: null,
    status(c) { this._s = c; return this; },
    setHeader(k, v) { this._h.set(k, v); return this; },
    end(b) { this._b = b; return this; }
  };
  await handler(req, res);
  return new Response(res._b, { status: res._s, headers: res._h });
}
