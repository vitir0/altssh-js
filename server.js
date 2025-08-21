/* Safe allowlisted proxy for Render.com + E2E encrypting endpoint */
const express = require("express");
const fetch = require("node-fetch");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();

// --- Config ---
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || ""; // запросы должны присылать заголовок x-api-key
const ALLOW_HOSTS = (process.env.ALLOW_HOSTS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
// пример: ALLOW_HOSTS="api.github.com,example.com"
const MAX_BODY = parseInt(process.env.MAX_BODY || "1048576", 10); // 1MB (обычный прокси)
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || "15000", 10); // 15s
const FOLLOW_REDIRECTS = parseInt(process.env.FOLLOW_REDIRECTS || "3", 10);

// Отдельный лимит буферизации для E2E (шифруем в памяти)
const E2E_MAX_RESPONSE = parseInt(process.env.E2E_MAX_RESPONSE || "5242880", 10); // 5MB

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

// ========= E2E helper =========
function b64(b) { return Buffer.from(b).toString("base64"); }
function b64toBuf(s) { return Buffer.from(s, "base64"); }

async function fetchUpstream(target, req, extraHeaders = {}) {
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
    if (lk === "x-api-key") continue; // не пробрасываем наш ключ наружу
    if (lk === "x-e2e-key") continue; // не пробрасываем клиентский ключ наружу
    outgoingHeaders[lk] = v;
  }
  Object.assign(outgoingHeaders, extraHeaders);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const fetchOpts = {
    method: req.method,
    headers: outgoingHeaders,
    redirect: FOLLOW_REDIRECTS > 0 ? "follow" : "manual",
    follow: FOLLOW_REDIRECTS,
    body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
    signal: controller.signal
  };

  try {
    const response = await fetch(target.toString(), fetchOpts);
    clearTimeout(timeout);
    return response;
  } catch (e) {
    clearTimeout(timeout);
    throw e;
  }
}

// ========= Новый эндпоинт: /proxy_e2e (AES-256-GCM) =========
// Использование: 
//   curl -H "x-api-key: ..." -H "x-e2e-key: <base64 32 bytes>" \
//     "https://<svc>.onrender.com/proxy_e2e?url=https%3A%2F%2Fapi.github.com%2Frate_limit"
app.all("/proxy_e2e", async (req, res) => {
  try {
    const rawUrl = req.query.url;
    if (!rawUrl) return res.status(400).json({ error: "Missing 'url' query param" });

    let target;
    try { target = new URL(rawUrl); } 
    catch { return res.status(400).json({ error: "Invalid URL" }); }

    // Разрешаем ТОЛЬКО https для апстрима (чтобы и там было шифрование)
    if (target.protocol !== "https:") {
      return res.status(400).json({ error: "Only HTTPS targets are allowed for E2E mode" });
    }

    const hostname = target.hostname.toLowerCase();
    if (ALLOW_HOSTS.length && !ALLOW_HOSTS.includes(hostname)) {
      return res.status(403).json({ error: "Host not allowed", host: hostname });
    }

    // Чтение клиентского E2E ключа (Base64, 32 байта)
    const keyB64 = req.get("x-e2e-key");
    if (!keyB64) return res.status(400).json({ error: "Missing 'x-e2e-key' header (base64 32 bytes)" });

    let key;
    try {
      key = b64toBuf(keyB64);
      if (key.length !== 32) throw new Error("bad key length");
    } catch {
      return res.status(400).json({ error: "Bad x-e2e-key: must be base64 of 32 bytes" });
    }

    // Скачиваем апстрим
    const upstream = await fetchUpstream(target, req);
    const status = upstream.status;

    // Снимаем ограниченные/лишние заголовки, оставим несколько полезных
    const passHeaders = {};
    const allowHeaderList = new Set(["content-type", "content-length", "last-modified", "etag", "date", "cache-control"]);
    for (const [k, v] of upstream.headers.entries()) {
      const lk = k.toLowerCase();
      if (allowHeaderList.has(lk)) passHeaders[lk] = v;
    }

    // Читаем тело (буферизуем до лимита)
    const chunks = [];
    let total = 0;
    for await (const chunk of upstream.body) {
      total += chunk.length;
      if (total > E2E_MAX_RESPONSE) {
        return res.status(413).json({ error: "Upstream body too large for E2E", limit: E2E_MAX_RESPONSE });
      }
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);

    // Шифруем AES-256-GCM
    const iv = crypto.randomBytes(12); // 96-битный IV для GCM
    const aad = Buffer.from(`${status}`); // AAD: включим код статуса (по желанию можно убрать)
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: body.length });

    const enc = Buffer.concat([cipher.update(body), cipher.final()]);
    const tag = cipher.getAuthTag();

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200).send(JSON.stringify({
      alg: "AES-256-GCM",
      iv: b64(iv),
      tag: b64(tag),
      ciphertext: b64(enc),
      status,
      headers: passHeaders
    }));
  } catch (err) {
    if (err.name === "AbortError") {
      return res.status(504).json({ error: "Upstream timeout" });
    }
    console.error(err);
    res.status(502).json({ error: "Upstream error" });
  }
});

// ========= Старый эндпоинт обычного прокси (без E2E) =========
app.all("/proxy", async (req, res) => {
  try {
    const rawUrl = req.query.url;
    if (!rawUrl) return res.status(400).json({ error: "Missing 'url' query param" });

    let target;
    try { target = new URL(rawUrl); }
    catch { return res.status(400).json({ error: "Invalid URL" }); }

    if (!["http:", "https:"].includes(target.protocol)) {
      return res.status(400).json({ error: "Only http/https protocols are allowed" });
    }

    const hostname = target.hostname.toLowerCase();
    if (ALLOW_HOSTS.length && !ALLOW_HOSTS.includes(hostname)) {
      return res.status(403).json({ error: "Host not allowed", host: hostname });
    }

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
      body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
      signal: controller.signal
    };

    const response = await fetch(target.toString(), fetchOpts);
    clearTimeout(timeout);

    res.status(response.status);
    for (const [k, v] of response.headers.entries()) {
      const lk = k.toLowerCase();
      if (hopByHop.has(lk)) continue;
      if (lk === "content-encoding") continue; // node-fetch уже разжал
      res.setHeader(k, v);
    }

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
