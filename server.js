/* Safe allowlisted proxy for Render.com */
const express = require("express");
const fetch = require("node-fetch");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

const app = express();

// --- Config ---
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || ""; // запросы должны присылать заголовок x-api-key
const ALLOW_HOSTS = (process.env.ALLOW_HOSTS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
// пример: ALLOW_HOSTS="api.github.com,example.com"
const MAX_BODY = parseInt(process.env.MAX_BODY || "1048576", 10); // 1MB
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || "15000", 10); // 15s
const FOLLOW_REDIRECTS = parseInt(process.env.FOLLOW_REDIRECTS || "3", 10);

// --- Middleware ---
app.use(helmet());
app.use(morgan("tiny"));
app.use(express.text({ type: "*/*", limit: MAX_BODY })); // прозрачно форвардим тело как текст/буфер

// простой rate limit (по IP)
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_PER_MIN || "60", 10),
  standardHeaders: true,
  legacyHeaders: false
}));

// проверка API-ключа
app.use((req, res, next) => {
  if (!API_KEY) return next(); // можно отключить проверку, если не установлен
  const key = req.get("x-api-key");
  if (key === API_KEY) return next();
  res.status(401).json({ error: "Unauthorized" });
});

// healthcheck
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// основная точка: /proxy?url=<encodedURL>
app.all("/proxy", async (req, res) => {
  try {
    const rawUrl = req.query.url;
    if (!rawUrl) return res.status(400).json({ error: "Missing 'url' query param" });

    let target;
    try {
      target = new URL(rawUrl);
    } catch {
      return res.status(400).json({ error: "Invalid URL" });
    }

    if (!["http:", "https:"].includes(target.protocol)) {
      return res.status(400).json({ error: "Only http/https protocols are allowed" });
    }

    const hostname = target.hostname.toLowerCase();

    if (ALLOW_HOSTS.length && !ALLOW_HOSTS.includes(hostname)) {
      return res.status(403).json({ error: "Host not allowed", host: hostname });
    }

    // соберём заголовки: уберём hop-by-hop, Host и сжатия
    const hopByHop = new Set([
      "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
      "te", "trailers", "transfer-encoding", "upgrade"
    ]);
    const outgoingHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (hopByHop.has(lk)) continue;
      if (lk === "host") continue;
      if (lk === "accept-encoding") continue; // упрощаем
      // не пробрасываем наш ключ наружу
      if (lk === "x-api-key") continue;
      outgoingHeaders[lk] = v;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const fetchOpts = {
      method: req.method,
      headers: outgoingHeaders,
      redirect: FOLLOW_REDIRECTS > 0 ? "follow" : "manual",
      follow: FOLLOW_REDIRECTS,
      // тело только для методов с телом
      body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
      signal: controller.signal
    };

    const response = await fetch(target.toString(), fetchOpts);
    clearTimeout(timeout);

    // прокинем статус и заголовки, убирая hop-by-hop
    res.status(response.status);
    for (const [k, v] of response.headers.entries()) {
      const lk = k.toLowerCase();
      if (hopByHop.has(lk)) continue;
      if (lk === "content-encoding") continue; // упрощаем; node-fetch уже разжал
      res.setHeader(k, v);
    }

    // стримим тело
    response.body.pipe(res);
  } catch (err) {
    if (err.name === "AbortError") {
      return res.status(504).json({ error: "Upstream timeout" });
    }
    console.error(err);
    res.status(502).json({ error: "Upstream error" });
  }
});

// 404 для всего остального
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
  console.log(`Safe proxy listening on :${PORT}`);
});
