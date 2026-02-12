/**
 * index.js — Mnemosyne Admin (Railway) — FULL FILE
 *
 * Includes:
 * - Discord OAuth login (no redirect loop; state checked; session saved before redirect)
 * - Postgres-backed sessions (connect-pg-simple) (survives restarts)
 * - Dark/Light mode toggle (stored in localStorage)
 * - Single “Admin Tools” block (no duplicate links)
 * - Birthdays CRUD:
 *    - /me/birthdays: view/add/edit/delete ONLY your own rows
 *    - /admin/birthdays: admin view + admin add for any user_id + admin delete
 *    - /admin/search: admin search by user_id OR character name OR username
 * - User directory:
 *    - /admin/users: list known users (username ↔ user_id) + counts
 *    - /admin/users/:id: manage birthdays for that user
 * - Stores username ↔ user_id automatically on login in discord_users table
 * - Admin Export + Import:
 *    - /admin/export.json
 *    - /admin/import
 *
 * Admin-only link:
 * - Dropbox backup link opens new tab (admin only)
 *
 * Favicon:
 * - Uses inline SVG data URL (no extra file needed)
 *
 * ENV REQUIRED:
 *   DATABASE_URL
 *   DISCORD_CLIENT_ID
 *   DISCORD_CLIENT_SECRET
 *   DISCORD_REDIRECT_URI     e.g. https://YOUR-SERVICE.up.railway.app/callback
 *   DISCORD_GUILD_ID
 *   BOT_TOKEN               (Discord bot token; used to look up guild roles)
 *   SESSION_SECRET
 *
 * ENV OPTIONAL:
 *   ADMIN_ROLE_IDS          comma-separated Discord role IDs that count as admin
 *   BIRTHDAYS_TABLE         defaults "birthdays"
 *   PORT                    defaults 3000
 *   PGSSLMODE               set "disable" to disable ssl
 */

import express from "express";
import session from "express-session";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import crypto from "crypto";

const { Pool } = pg;
const PgSession = connectPgSimple(session);
const app = express();

// ---------------- Env helpers ----------------
function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const PORT = Number(process.env.PORT || 3000);

const DATABASE_URL = requireEnv("DATABASE_URL");
const DISCORD_CLIENT_ID = requireEnv("DISCORD_CLIENT_ID");
const DISCORD_CLIENT_SECRET = requireEnv("DISCORD_CLIENT_SECRET");
const DISCORD_REDIRECT_URI = requireEnv("DISCORD_REDIRECT_URI");
const DISCORD_GUILD_ID = requireEnv("DISCORD_GUILD_ID");
const BOT_TOKEN = requireEnv("BOT_TOKEN");
const SESSION_SECRET = requireEnv("SESSION_SECRET");

const BIRTHDAYS_TABLE = process.env.BIRTHDAYS_TABLE || "birthdays";

const ADMIN_ROLE_IDS = (process.env.ADMIN_ROLE_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ---------------- Postgres ----------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : undefined,
});

// ---------------- Express / Sessions ----------------
app.set("trust proxy", 1); // needed on Railway for secure cookies behind proxy
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: "web_sessions",
      createTableIfMissing: true,
    }),
    name: "mnemo.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true, // Railway URL is https
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---------------- Utilities ----------------
function escapeHtml(s = "") {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function cleanName(name) {
  return String(name || "").replace(/\s+/g, " ").trim();
}

function charKey(name) {
  return cleanName(name).toLowerCase();
}

function randomState() {
  return crypto.randomBytes(16).toString("hex");
}

function isAdminByRoles(roleIds) {
  if (!ADMIN_ROLE_IDS.length) return false;
  return roleIds.some((r) => ADMIN_ROLE_IDS.includes(String(r)));
}

function mustBeAuthed(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function mustBeAdmin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  if (!req.session.user.is_admin) return res.status(403).send("Forbidden (admin only)");
  next();
}

function mmddValid(mmdd) {
  return /^(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(String(mmdd || ""));
}

function parseMmdd(mmdd) {
  const [m, d] = String(mmdd).split("-").map((x) => Number(x));
  return [m, d];
}

function safeIntStringDiscordId(s) {
  const t = String(s || "").trim();
  return /^\d{15,25}$/.test(t) ? t : null;
}

function tableIdent(name) {
  // allow only safe identifiers to avoid injection via env
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(`Unsafe table name: ${name}`);
  return `"${name}"`;
}

const TBL = tableIdent(BIRTHDAYS_TABLE);

// ---------------- Schema ensure ----------------
async function ensureSchema() {
  // 0) users table (username ↔ user_id)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS discord_users (
      user_id text PRIMARY KEY,
      username text NOT NULL,
      avatar text,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  // 1) Dedupe table (optional but harmless)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS birthday_shouts (
      shout_date date NOT NULL,
      user_id text NOT NULL,
      character_name_key text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (shout_date, user_id, character_name_key)
    );
  `);

  // 2) Birthdays table (create if missing)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${TBL} (
      id SERIAL PRIMARY KEY,
      user_id text NOT NULL,
      character_name text NOT NULL,
      character_name_key text NOT NULL,
      month integer NOT NULL CHECK (month BETWEEN 1 AND 12),
      day integer NOT NULL CHECK (day BETWEEN 1 AND 31),
      image_url text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  // 3) Backfill character_name_key if any blanks/nulls exist (safe)
  await pool.query(`
    UPDATE ${TBL}
    SET character_name_key = lower(btrim(regexp_replace(coalesce(character_name,''), '\\s+', ' ', 'g')))
    WHERE character_name_key IS NULL OR btrim(character_name_key) = '';
  `);

  // 4) Unique index supports ON CONFLICT (user_id, character_name_key)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS birthdays_user_char_key_unique
    ON ${TBL} (user_id, character_name_key);
  `);

  // 5) Helpful indexes
  await pool.query(`
    CREATE INDEX IF NOT EXISTS birthdays_mmdd_idx
    ON ${TBL} (month, day);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS discord_users_username_idx
    ON discord_users (lower(username));
  `);
}

// Run once on boot
ensureSchema().catch((e) => {
  console.error("[BOOT] schema ensure failed:", e);
  process.exit(1);
});

// ---------------- Discord OAuth helpers ----------------
async function discordTokenExchange(code) {
  const body = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    client_secret: DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: DISCORD_REDIRECT_URI,
  });

  const r = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  const text = await r.text();
  if (!r.ok) throw new Error(`Token exchange failed: ${r.status} ${text}`);
  return JSON.parse(text);
}

async function discordGetUser(accessToken) {
  const r = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`Get user failed: ${r.status} ${text}`);
  return JSON.parse(text);
}

async function discordGetMemberRoles(userId) {
  const r = await fetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`,
    { headers: { Authorization: `Bot ${BOT_TOKEN}` } }
  );

  const text = await r.text();
  if (!r.ok) {
    console.warn("[DISCORD] member lookup failed:", r.status, text);
    return [];
  }

  const member = JSON.parse(text);
  return Array.isArray(member.roles) ? member.roles : [];
}

async function upsertDiscordUser({ user_id, username, avatar }) {
  await pool.query(
    `
    INSERT INTO discord_users (user_id, username, avatar, updated_at)
    VALUES ($1, $2, $3, now())
    ON CONFLICT (user_id)
    DO UPDATE SET
      username = EXCLUDED.username,
      avatar = EXCLUDED.avatar,
      updated_at = now()
    `,
    [String(user_id), String(username), avatar ? String(avatar) : null]
  );
}

// ---------------- UI rendering helpers ----------------
const DROPBOX_ADMIN_URL = "https://www.dropbox.com/home/Grass%20Is%20Greener%20Backup";

function faviconDataUrl() {
  // Simple “Mnemosyne” owl-ish glyph icon (SVG) as a data URL
  const svg = `
  <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
    <defs>
      <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="#7c5cff"/>
        <stop offset="1" stop-color="#22c55e"/>
      </linearGradient>
    </defs>
    <rect width="64" height="64" rx="14" fill="#0b0f19"/>
    <path d="M18 28c3-10 25-10 28 0 0 14-7 22-14 22S18 42 18 28z" fill="url(#g)"/>
    <circle cx="26" cy="32" r="4" fill="#0b0f19"/>
    <circle cx="38" cy="32" r="4" fill="#0b0f19"/>
    <path d="M32 36l4 6h-8l4-6z" fill="#0b0f19"/>
  </svg>`;
  const encoded = encodeURIComponent(svg).replaceAll("'", "%27").replaceAll('"', "%22");
  return `data:image/svg+xml,${encoded}`;
}

function renderPage({ title, user, bodyHtml }) {
  const isAdmin = Boolean(user?.is_admin);

  // Admin tools only once, and only for admins.
  const adminTools = isAdmin
    ? `
    <div class="card">
      <div class="card-title">Admin Tools</div>
      <div class="grid">
        <a class="btn" href="/admin/users">User Directory</a>
        <a class="btn" href="/admin/search">Search</a>
        <a class="btn" href="/admin/export.json" target="_blank" rel="noreferrer">Export JSON</a>
        <a class="btn" href="/admin/import">Import JSON</a>
        <a class="btn" href="${DROPBOX_ADMIN_URL}" target="_blank" rel="noreferrer">Open Dropbox Backup</a>
      </div>
      <div class="muted small" style="margin-top:10px;">
        Tip: Export JSON regularly before big changes.
      </div>
    </div>
  `
    : "";

  const header = `
    <div class="topbar">
      <div class="brand">
        <div class="logo"><img src = "https://b.l3n.co/UivoNb.jpeg"/></div>
        <div>
          <div class="brand-title">Mnemosyne Admin</div>
          <div class="brand-sub">Birthdays dashboard</div>
        </div>
      </div>

      <div class="topbar-right">
        <button class="btn ghost" id="themeToggle" type="button" title="Toggle theme">🌓</button>
        ${
          user
            ? `<span class="pill">👤 ${escapeHtml(user.username)}${isAdmin ? " • admin" : ""}</span>
               <a class="btn danger" href="/logout">Logout</a>`
            : `<a class="btn" href="/login">Login with Discord</a>`
        }
      </div>
    </div>
  `;

  const css = `
  :root{
    --bg:#0b0f19;
    --panel:#111827;
    --panel2:#0f172a;
    --text:#e5e7eb;
    --muted:#9ca3af;
    --border:#243047;
    --accent:#7c5cff;
    --ok:#22c55e;
    --danger:#ef4444;
    --link:#93c5fd;
    --shadow: 0 10px 30px rgba(0,0,0,.35);
  }
  [data-theme="light"]{
    --bg:#f7f7fb;
    --panel:#ffffff;
    --panel2:#f1f5f9;
    --text:#0b1020;
    --muted:#475569;
    --border:#dbe3f0;
    --accent:#6d28d9;
    --ok:#16a34a;
    --danger:#dc2626;
    --link:#1d4ed8;
    --shadow: 0 10px 30px rgba(2,6,23,.12);
  }

  *{box-sizing:border-box}
  body{
    margin:0;
    font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
  }
  a{color:var(--link); text-decoration:none}
  a:hover{text-decoration:underline}

  .container{max-width:1100px; margin:0 auto; padding:20px;}
  .topbar{
    display:flex; align-items:center; justify-content:space-between;
    padding:16px 20px; border-bottom:1px solid var(--border);
    background: linear-gradient(180deg, rgba(124,92,255,.12), transparent 60%);
    position:sticky; top:0; backdrop-filter: blur(8px);
  }
  .brand{display:flex; gap:12px; align-items:center;}
  .logo img{
    width:38px; height:38px; border-radius:12px;
    display:flex; align-items:center; justify-content:center;
    background: radial-gradient(circle at 30% 30%, var(--accent), rgba(34,197,94,.55));
    color:white; font-weight:800;
    box-shadow: var(--shadow);
  }
  .brand-title{font-weight:800; letter-spacing:.2px}
  .brand-sub{font-size:12px; color:var(--muted); margin-top:2px}
  .topbar-right{display:flex; gap:10px; align-items:center; flex-wrap:wrap}

  .pill{
    padding:8px 10px; border:1px solid var(--border);
    background: rgba(255,255,255,.03);
    border-radius:999px; font-size:13px;
  }

  .card{
    background: linear-gradient(180deg, rgba(255,255,255,.04), transparent 60%), var(--panel);
    border:1px solid var(--border);
    border-radius:16px;
    padding:16px;
    box-shadow: var(--shadow);
    margin:16px 0;
  }
  .card-title{font-weight:800; margin-bottom:10px}
  .muted{color:var(--muted)}
  .small{font-size:12px}
  .grid{display:flex; flex-wrap:wrap; gap:10px}

  .btn{
    display:inline-flex; align-items:center; justify-content:center;
    gap:8px;
    padding:10px 12px;
    border-radius:12px;
    border:1px solid var(--border);
    background: rgba(255,255,255,.04);
    color: var(--text);
    cursor:pointer;
    text-decoration:none;
    font-weight:700;
  }
  .btn:hover{filter:brightness(1.08); text-decoration:none}
  .btn.primary{border-color: rgba(124,92,255,.6); background: rgba(124,92,255,.18)}
  .btn.ok{border-color: rgba(34,197,94,.6); background: rgba(34,197,94,.15)}
  .btn.danger{border-color: rgba(239,68,68,.6); background: rgba(239,68,68,.14)}
  .btn.ghost{background:transparent}

  input, textarea{
    width:100%;
    padding:10px 12px;
    border-radius:12px;
    border:1px solid var(--border);
    background: var(--panel2);
    color: var(--text);
    outline:none;
  }
  input::placeholder{color: rgba(156,163,175,.8)}
  label{font-size:13px; color: var(--muted)}
  .row{display:flex; gap:12px; flex-wrap:wrap}
  .col{flex:1; min-width:220px}

  table{
    width:100%;
    border-collapse:collapse;
    overflow:hidden;
    border-radius:14px;
    border:1px solid var(--border);
  }
  th, td{
    padding:10px 10px;
    border-bottom:1px solid var(--border);
    vertical-align:top;
    font-size:14px;
  }
  th{
    text-align:left;
    background: rgba(255,255,255,.05);
    font-weight:800;
  }
  tr:hover td{background: rgba(124,92,255,.06)}
  .mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size:13px}

  details summary{cursor:pointer; color: var(--link); font-weight:700}
  .spacer{height:10px}

  .footer{
    margin:24px 0 10px;
    color: var(--muted);
    font-size:12px;
    text-align:center;
  }
  `;

  const themeScript = `
  <script>
    (function(){
      const key = "mnemo_theme";
      const saved = localStorage.getItem(key);
      if(saved === "light" || saved === "dark"){
        document.documentElement.setAttribute("data-theme", saved);
      } else {
        // default: dark
        document.documentElement.setAttribute("data-theme", "dark");
      }

      function toggle(){
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem(key, next);
      }

      window.addEventListener("DOMContentLoaded", () => {
        const btn = document.getElementById("themeToggle");
        if(btn) btn.addEventListener("click", toggle);
      });
    })();
  </script>
  `;

  return `
  <!doctype html>
  <html>
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width,initial-scale=1"/>
      <title>${escapeHtml(title || "Mnemosyne Admin")}</title>
      <link rel="icon" href="${faviconDataUrl()}">
      <style>${css}</style>
    </head>
    <body>
      ${header}
      <div class="container">
        ${adminTools}
        ${bodyHtml || ""}
        <div class="footer">Mnemosyne • Railway • Postgres • OAuth</div>
      </div>
      ${themeScript}
    </body>
  </html>
  `;
}

// ---------------- Routes ----------------
app.get("/", (req, res) => {
  const user = req.session.user || null;

  const bodyHtml = `
    <div class="card">
      <div class="card-title">Welcome</div>
      ${
        user
          ? `
        <div class="muted">You’re logged in. Use the buttons below.</div>
        <div class="spacer"></div>
        <div class="grid">
          <a class="btn primary" href="/me/birthdays">My Birthdays</a>
          ${user.is_admin ? `<a class="btn" href="/admin/birthdays">Admin: All Birthdays</a>` : ""}
          <a class="btn" href="/health">Health</a>
        </div>
      `
          : `
        <div class="muted">Login to manage your birthdays.</div>
        <div class="spacer"></div>
        <div class="grid">
          <a class="btn primary" href="/login">Login with Discord</a>
          <a class="btn" href="/health">Health</a>
        </div>
      `
      }
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Home", user, bodyHtml }));
});

// OAuth start
app.get("/login", (req, res) => {
  const state = randomState();
  req.session.oauth_state = state;

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify",
    state,
  });

  req.session.save((err) => {
    if (err) console.error("[SESSION] save before login redirect failed:", err);
    res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
  });
});

// OAuth callback
app.get("/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state;

    if (!code) return res.status(400).send("Missing ?code");
    if (!state || state !== req.session.oauth_state) {
      return res.status(400).send("OAuth state mismatch. Please go to /login again.");
    }

    const token = await discordTokenExchange(code);
    const user = await discordGetUser(token.access_token);
    const roles = await discordGetMemberRoles(user.id);

    // Store user mapping in DB so admin can search by username later
    await upsertDiscordUser({ user_id: user.id, username: user.username, avatar: user.avatar });

    req.session.user = {
      id: user.id,
      username: user.username,
      discriminator: user.discriminator,
      avatar: user.avatar,
      is_admin: isAdminByRoles(roles),
    };

    delete req.session.oauth_state;

    req.session.save((err) => {
      if (err) {
        console.error("[SESSION] save error:", err);
        return res.status(500).send("Session save failed");
      }
      res.redirect("/me/birthdays");
    });
  } catch (e) {
    console.error("[OAUTH] error:", e);
    res.status(500).send(`OAuth error: ${escapeHtml(e.message)}`);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ---------------- Per-user birthdays ----------------
app.get("/me/birthdays", mustBeAuthed, async (req, res) => {
  const user = req.session.user;
  const userId = String(user.id);

  const { rows } = await pool.query(
    `SELECT id, character_name, month, day, image_url
     FROM ${TBL}
     WHERE user_id=$1
     ORDER BY month ASC, day ASC, character_name_key ASC`,
    [userId]
  );

  const bodyHtml = `
    <div class="card">
      <div class="card-title">My Birthdays</div>
      <div class="muted small">Only you can see & edit these rows.</div>

      <div class="spacer"></div>

      <form method="POST" action="/me/birthdays">
        <div class="row">
          <div class="col">
            <label>Character Name</label>
            <input name="character_name" required placeholder="Cash Langston"/>
          </div>
          <div style="width:140px">
            <label>Date (MM-DD)</label>
            <input name="mmdd" required placeholder="07-12"/>
          </div>
          <div class="col">
            <label>Image URL (optional)</label>
            <input name="image_url" placeholder="https://...png"/>
          </div>
        </div>
        <div class="spacer"></div>
        <button class="btn ok" type="submit">Add / Update</button>
      </form>
    </div>

    <div class="card">
      <div class="card-title">Your list</div>
      ${
        rows.length
          ? `
        <div style="overflow:auto;">
          <table>
            <thead><tr><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td class="mono">${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${
                    r.image_url
                      ? `<a href="${escapeHtml(r.image_url)}" target="_blank" rel="noreferrer">link</a>`
                      : `<span class="muted small">—</span>`
                  }</td>
                  <td>
                    <form method="POST" action="/me/birthdays/${r.id}/delete" style="display:inline;">
                      <button class="btn danger" type="submit" onclick="return confirm('Delete this birthday?')">Delete</button>
                    </form>
                    <details style="display:inline-block; margin-left:10px;">
                      <summary>Edit</summary>
                      <div class="spacer"></div>
                      <form method="POST" action="/me/birthdays/${r.id}/edit">
                        <div class="row">
                          <div class="col">
                            <label>Name</label>
                            <input name="character_name" value="${escapeHtml(r.character_name)}" required/>
                          </div>
                          <div style="width:140px">
                            <label>MM-DD</label>
                            <input name="mmdd" value="${String(r.month).padStart(2, "0")}-${String(r.day).padStart(
                              2,
                              "0"
                            )}" required/>
                          </div>
                          <div class="col">
                            <label>Image URL</label>
                            <input name="image_url" value="${escapeHtml(r.image_url || "")}"/>
                          </div>
                        </div>
                        <div class="spacer"></div>
                        <button class="btn primary" type="submit">Save</button>
                      </form>
                    </details>
                  </td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `
          : `<div class="muted">No birthdays yet.</div>`
      }
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "My Birthdays", user, bodyHtml }));
});

app.post("/me/birthdays", mustBeAuthed, async (req, res) => {
  try {
    const userId = String(req.session.user.id);
    const character_name = cleanName(req.body.character_name);
    const mmdd = String(req.body.mmdd || "");
    const image_url = cleanName(req.body.image_url || "");

    if (!character_name) return res.status(400).send("Missing character_name");
    if (!mmddValid(mmdd)) return res.status(400).send("Invalid mmdd (use MM-DD)");

    const [m, d] = parseMmdd(mmdd);
    const character_name_key = charKey(character_name);

    await pool.query(
      `
      INSERT INTO ${TBL} (user_id, character_name, character_name_key, month, day, image_url, updated_at)
      VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), now())
      ON CONFLICT (user_id, character_name_key)
      DO UPDATE SET
        character_name = EXCLUDED.character_name,
        month = EXCLUDED.month,
        day = EXCLUDED.day,
        image_url = EXCLUDED.image_url,
        updated_at = now()
      `,
      [userId, character_name, character_name_key, m, d, image_url]
    );

    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[ADD ME] error:", e);
    res.status(500).send(`Add failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/me/birthdays/:id/edit", mustBeAuthed, async (req, res) => {
  try {
    const userId = String(req.session.user.id);
    const id = Number(req.params.id);

    const character_name = cleanName(req.body.character_name);
    const mmdd = String(req.body.mmdd || "");
    const image_url = cleanName(req.body.image_url || "");

    if (!id) return res.status(400).send("Bad id");
    if (!character_name) return res.status(400).send("Missing character_name");
    if (!mmddValid(mmdd)) return res.status(400).send("Invalid mmdd (use MM-DD)");

    const [m, d] = parseMmdd(mmdd);
    const character_name_key = charKey(character_name);

    await pool.query(
      `
      UPDATE ${TBL}
      SET character_name=$1,
          character_name_key=$2,
          month=$3,
          day=$4,
          image_url=NULLIF($5,''),
          updated_at=now()
      WHERE id=$6 AND user_id=$7
      `,
      [character_name, character_name_key, m, d, image_url, id, userId]
    );

    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[EDIT ME] error:", e);
    res.status(500).send(`Edit failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/me/birthdays/:id/delete", mustBeAuthed, async (req, res) => {
  try {
    const userId = String(req.session.user.id);
    const id = Number(req.params.id);
    if (!id) return res.status(400).send("Bad id");

    await pool.query(`DELETE FROM ${TBL} WHERE id=$1 AND user_id=$2`, [id, userId]);
    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[DEL ME] error:", e);
    res.status(500).send(`Delete failed: ${escapeHtml(e.message)}`);
  }
});

// ---------------- Admin: User Directory ----------------
app.get("/admin/users", mustBeAdmin, async (req, res) => {
  const user = req.session.user;

  const { rows } = await pool.query(
    `
    SELECT
      u.user_id,
      u.username,
      u.avatar,
      COUNT(b.id)::int AS birthday_count
    FROM discord_users u
    LEFT JOIN ${TBL} b ON b.user_id = u.user_id
    GROUP BY u.user_id, u.username, u.avatar
    ORDER BY lower(u.username) ASC
    `
  );

  const bodyHtml = `
    <div class="card">
      <div class="card-title">Admin: User Directory</div>
      <div class="muted small">Users appear here after they log in at least once.</div>
    </div>

    <div class="card">
      <div class="card-title">Users (${rows.length})</div>
      ${
        rows.length
          ? `
        <div style="overflow:auto;">
          <table>
            <thead><tr><th>User</th><th>User ID</th><th># Birthdays</th><th>Manage</th></tr></thead>
            <tbody>
              ${rows
                .map((r) => {
                  const avatarUrl =
                    r.avatar && r.user_id
                      ? `https://cdn.discordapp.com/avatars/${encodeURIComponent(r.user_id)}/${encodeURIComponent(
                          r.avatar
                        )}.png?size=64`
                      : null;

                  return `
                    <tr>
                      <td>
                        <div style="display:flex; align-items:center; gap:10px;">
                          ${
                            avatarUrl
                              ? `<img src="${escapeHtml(
                                  avatarUrl
                                )}" width="32" height="32" style="border-radius:10px; border:1px solid var(--border);" />`
                              : `<div style="width:32px;height:32px;border-radius:10px;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;" class="muted">?</div>`
                          }
                          <div>
                            <div><b>${escapeHtml(r.username)}</b></div>
                            <div class="muted small mono">${escapeHtml(r.user_id)}</div>
                          </div>
                        </div>
                      </td>
                      <td class="mono">${escapeHtml(r.user_id)}</td>
                      <td class="mono">${Number(r.birthday_count || 0)}</td>
                     <td>
                      <a class="btn" href="/admin/users/${encodeURIComponent(u.user_id)}">Manage</a>

                      <form method="POST"
                            action="/admin/users/${encodeURIComponent(u.user_id)}/delete"
                            style="display:inline; margin-left:8px;">
                        <input type="hidden" name="delete_mapping" value="yes" />
                        <button class="btn danger" type="submit"
                          onclick="return confirm('Delete this user? This will delete ALL birthdays for them.');">
                          Delete
                      </button>
                    </form>
                  </td>

                    </tr>
                  `;
                })
                .join("")}
            </tbody>
          </table>
        </div>
      `
          : `<div class="muted">No users yet.</div>`
      }
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Admin: Users", user, bodyHtml }));
});

app.get("/admin/users/:id", mustBeAdmin, async (req, res) => {
  const user = req.session.user;
  const targetUserId = safeIntStringDiscordId(req.params.id);

  if (!targetUserId) return res.status(400).send("Bad user id");

  const u = await pool.query(
    `SELECT user_id, username, avatar FROM discord_users WHERE user_id=$1`,
    [targetUserId]
  );

  const userRow = u.rows[0] || { user_id: targetUserId, username: "unknown", avatar: null };

  const b = await pool.query(
    `SELECT id, character_name, month, day, image_url
     FROM ${TBL}
     WHERE user_id=$1
     ORDER BY month ASC, day ASC, character_name_key ASC`,
    [targetUserId]
  );

  const avatarUrl =
    userRow.avatar && userRow.user_id
      ? `https://cdn.discordapp.com/avatars/${encodeURIComponent(userRow.user_id)}/${encodeURIComponent(
          userRow.avatar
        )}.png?size=96`
      : null;

  const bodyHtml = `
    <div class="card">
      <div class="card-title">Admin: Manage User</div>
      <div style="display:flex; align-items:center; gap:12px;">
        ${
          avatarUrl
            ? `<img src="${escapeHtml(
                avatarUrl
              )}" width="44" height="44" style="border-radius:14px; border:1px solid var(--border);" />`
            : `<div style="width:44px;height:44px;border-radius:14px;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;" class="muted">?</div>`
        }
        <div>
          <div><b>${escapeHtml(userRow.username)}</b></div>
          <div class="muted small mono">${escapeHtml(targetUserId)}</div>
        </div>
      </div>

      <div class="spacer"></div>

      <form method="POST" action="/admin/users/${encodeURIComponent(targetUserId)}/add">
        <div class="row">
          <div class="col">
            <label>Character Name</label>
            <input name="character_name" required placeholder="Cash Langston"/>
          </div>
          <div style="width:140px">
            <label>Date (MM-DD)</label>
            <input name="mmdd" required placeholder="07-12"/>
          </div>
          <div class="col">
            <label>Image URL (optional)</label>
            <input name="image_url" placeholder="https://...png"/>
          </div>
        </div>
        <div class="spacer"></div>
        <button class="btn ok" type="submit">Add / Update for this user</button>
        <a class="btn" href="/admin/users">Back to directory</a>
      </form>
    </div>

    <div class="card">
      <div class="card-title">Birthdays for ${escapeHtml(userRow.username)}</div>
      ${
        b.rows.length
          ? `
        <div style="overflow:auto;">
          <table>
            <thead><tr><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${b.rows
                .map(
                  (r) => `
                <tr>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td class="mono">${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank" rel="noreferrer">link</a>` : `<span class="muted small">—</span>`}</td>
                  <td>
                    <form method="POST" action="/admin/birthdays/${r.id}/delete" style="display:inline;">
                      <button class="btn danger" type="submit" onclick="return confirm('Admin delete this birthday?')">Delete</button>
                    </form>
                  </td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `
          : `<div class="muted">No birthdays for this user yet.</div>`
      }
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Admin: Manage User", user, bodyHtml }));
});

app.post("/admin/users/:id/add", mustBeAdmin, async (req, res) => {
  try {
    const targetUserId = safeIntStringDiscordId(req.params.id);
    if (!targetUserId) return res.status(400).send("Bad user id");

    const character_name = cleanName(req.body.character_name);
    const mmdd = String(req.body.mmdd || "");
    const image_url = cleanName(req.body.image_url || "");

    if (!character_name) return res.status(400).send("Missing character_name");
    if (!mmddValid(mmdd)) return res.status(400).send("Invalid mmdd (use MM-DD)");

    const [m, d] = parseMmdd(mmdd);
    const character_name_key = charKey(character_name);

    await pool.query(
      `
      INSERT INTO ${TBL} (user_id, character_name, character_name_key, month, day, image_url, updated_at)
      VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), now())
      ON CONFLICT (user_id, character_name_key)
      DO UPDATE SET
        character_name = EXCLUDED.character_name,
        month = EXCLUDED.month,
        day = EXCLUDED.day,
        image_url = EXCLUDED.image_url,
        updated_at = now()
      `,
      [targetUserId, character_name, character_name_key, m, d, image_url]
    );

    res.redirect(`/admin/users/${encodeURIComponent(targetUserId)}`);
  } catch (e) {
    console.error("[ADMIN USER ADD] error:", e);
    res.status(500).send(`Admin add failed: ${escapeHtml(e.message)}`);
  }
});

// ---------------- Admin Search (user_id OR character OR username) ----------------
app.get("/admin/search", mustBeAdmin, async (req, res) => {
  const user = req.session.user;
  const q = String(req.query.q || "").trim();
  let rows = [];

  if (q) {
    const asId = safeIntStringDiscordId(q);

    if (asId) {
      const r = await pool.query(
        `
        SELECT b.id, b.user_id, u.username, b.character_name, b.month, b.day, b.image_url
        FROM ${TBL} b
        LEFT JOIN discord_users u ON u.user_id = b.user_id
        WHERE b.user_id=$1
        ORDER BY b.month ASC, b.day ASC, b.character_name_key ASC
        `,
        [asId]
      );
      rows = r.rows;
    } else {
      // Search:
      // 1) username match in discord_users
      // 2) character name substring in birthdays
      const r = await pool.query(
        `
        SELECT b.id, b.user_id, u.username, b.character_name, b.month, b.day, b.image_url
        FROM ${TBL} b
        LEFT JOIN discord_users u ON u.user_id = b.user_id
        WHERE
          b.character_name ILIKE $1
          OR u.username ILIKE $1
        ORDER BY b.month ASC, b.day ASC, b.character_name_key ASC
        LIMIT 300
        `,
        [`%${q}%`]
      );
      rows = r.rows;
    }
  }

  const bodyHtml = `
    <div class="card">
      <div class="card-title">Admin: Search</div>
      <form method="GET" action="/admin/search">
        <div class="row">
          <div class="col">
            <label>Search by Discord User ID, Username, or Character Name</label>
            <input name="q" value="${escapeHtml(q)}" placeholder="e.g. 123456789012345678 OR MandyWinslow OR Cash"/>
          </div>
          <div style="width:180px; align-self:end;">
            <button class="btn primary" type="submit">Search</button>
          </div>
        </div>
      </form>
      <div class="spacer"></div>
      <div class="muted small">
        Tip: Usernames are available after someone logs in at least once.
      </div>
    </div>

    <div class="card">
      <div class="card-title">Results</div>
      ${
        q
          ? `<div class="muted small">Results for <b>${escapeHtml(q)}</b>: ${rows.length}</div>`
          : `<div class="muted small">Enter a search term above.</div>`
      }

      <div class="spacer"></div>

      ${
        rows.length
          ? `
        <div style="overflow:auto;">
          <table>
            <thead><tr><th>User</th><th>User ID</th><th>Character</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td>${r.username ? escapeHtml(r.username) : `<span class="muted">unknown</span>`}</td>
                  <td class="mono">${escapeHtml(r.user_id)}</td>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td class="mono">${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank" rel="noreferrer">link</a>` : `<span class="muted small">—</span>`}</td>
                  <td>
                    <a class="btn" href="/admin/users/${encodeURIComponent(r.user_id)}">Manage user</a>
                    <form method="POST" action="/admin/birthdays/${r.id}/delete" style="display:inline;">
                      <button class="btn danger" type="submit" onclick="return confirm('Admin delete this birthday?')">Delete</button>
                    </form>
                  </td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `
          : q
          ? `<div class="muted">No matches.</div>`
          : ``
      }
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Admin: Search", user, bodyHtml }));
});

// ---------------- Admin Export JSON ----------------
app.get("/admin/export.json", mustBeAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT user_id, character_name, character_name_key, month, day, image_url
     FROM ${TBL}
     ORDER BY user_id ASC, month ASC, day ASC, character_name_key ASC`
  );

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("content-disposition", `attachment; filename="mnemosyne-backup-${stamp}.json"`);

  res.send(
    JSON.stringify(
      {
        exported_at: new Date().toISOString(),
        table: BIRTHDAYS_TABLE,
        count: rows.length,
        rows,
      },
      null,
      2
    )
  );
});

// ---------------- Admin Import ----------------
app.get("/admin/import", mustBeAdmin, async (req, res) => {
  const user = req.session.user;

  const bodyHtml = `
    <div class="card">
      <div class="card-title">Admin: Import JSON Backup</div>
      <div class="muted small">
        This will <b>upsert</b> rows into the database (insert new + update existing).
        It will not delete rows that are not present in the import.
      </div>
    </div>

    <div class="card">
      <div class="card-title">Paste JSON</div>
      <form method="POST" action="/admin/import">
        <label>JSON backup</label>
        <textarea name="json" rows="16" required placeholder='Paste export.json contents here...'></textarea>
        <div class="spacer"></div>
        <label><input type="checkbox" name="confirm" value="yes" required/> I understand this will modify the database.</label>
        <div class="spacer"></div>
        <button class="btn ok" type="submit">Import</button>
        <a class="btn" href="/admin/birthdays">Back</a>
      </form>
    </div>

    <div class="card">
      <div class="card-title">Supported formats</div>
      <pre class="mono" style="white-space:pre-wrap; background: rgba(255,255,255,.03); padding:12px; border-radius:12px; border:1px solid var(--border); overflow:auto;">
1) Export format from this site:
{
  "exported_at":"...",
  "table":"birthdays",
  "count": 123,
  "rows":[
    {"user_id":"...","character_name":"...","character_name_key":"...","month":1,"day":2,"image_url":"..."}
  ]
}

2) Legacy bot JSON:
{
  "1234567890123": [
    ["Cash Langston","07-12","https://...png"]
  ]
}
      </pre>
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Admin: Import", user, bodyHtml }));
});

function isRowFormat(obj) {
  return obj && typeof obj === "object" && "user_id" in obj && "character_name" in obj;
}
function isLegacyFormat(obj) {
  return obj && typeof obj === "object" && !Array.isArray(obj) && !("rows" in obj);
}
function parseLegacyEntry(entry) {
  if (!Array.isArray(entry) || entry.length < 2) return null;
  const character_name = cleanName(entry[0]);
  const mmdd = String(entry[1] || "");
  const image_url = cleanName(entry[2] || "");

  if (!character_name) return null;
  if (!mmddValid(mmdd)) return null;

  const [m, d] = mmdd.split("-").map((x) => Number(x));
  return {
    character_name,
    character_name_key: charKey(character_name),
    month: m,
    day: d,
    image_url: image_url || null,
  };
}

app.post("/admin/import", mustBeAdmin, async (req, res) => {
  try {
    if (req.body.confirm !== "yes") return res.status(400).send("Missing confirmation checkbox.");

    const raw = String(req.body.json || "").trim();
    if (!raw) return res.status(400).send("Missing JSON body.");

    let payload;
    try {
      payload = JSON.parse(raw);
    } catch {
      return res.status(400).send("Invalid JSON.");
    }

    let rowsToImport = [];

    if (payload && typeof payload === "object" && Array.isArray(payload.rows)) {
      for (const r of payload.rows) {
        if (!isRowFormat(r)) continue;
        const user_id = safeIntStringDiscordId(r.user_id) || String(r.user_id || "").trim();
        const character_name = cleanName(r.character_name);
        const character_name_key = cleanName(r.character_name_key || charKey(character_name));
        const month = Number(r.month);
        const day = Number(r.day);
        const image_url = cleanName(r.image_url || "") || null;

        if (!user_id || !character_name || !character_name_key) continue;
        if (!(month >= 1 && month <= 12)) continue;
        if (!(day >= 1 && day <= 31)) continue;

        rowsToImport.push({ user_id, character_name, character_name_key, month, day, image_url });
      }
    } else if (Array.isArray(payload)) {
      for (const r of payload) {
        if (!isRowFormat(r)) continue;
        const user_id = safeIntStringDiscordId(r.user_id) || String(r.user_id || "").trim();
        const character_name = cleanName(r.character_name);
        const character_name_key = cleanName(r.character_name_key || charKey(character_name));
        const month = Number(r.month);
        const day = Number(r.day);
        const image_url = cleanName(r.image_url || "") || null;

        if (!user_id || !character_name || !character_name_key) continue;
        if (!(month >= 1 && month <= 12)) continue;
        if (!(day >= 1 && day <= 31)) continue;

        rowsToImport.push({ user_id, character_name, character_name_key, month, day, image_url });
      }
    } else if (isLegacyFormat(payload)) {
      for (const [uid, list] of Object.entries(payload)) {
        const user_id = safeIntStringDiscordId(uid) || String(uid || "").trim();
        if (!Array.isArray(list) || !user_id) continue;
        for (const entry of list) {
          const parsed = parseLegacyEntry(entry);
          if (!parsed) continue;
          rowsToImport.push({ user_id, ...parsed });
        }
      }
    } else {
      return res.status(400).send("Unrecognized JSON format.");
    }

    if (!rowsToImport.length) return res.status(400).send("No valid rows found in JSON.");

    const client = await pool.connect();
    let imported = 0;

    try {
      await client.query("BEGIN");

      await client.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS birthdays_user_char_key_unique
        ON ${TBL} (user_id, character_name_key);
      `);

      for (const r of rowsToImport) {
        await client.query(
          `
          INSERT INTO ${TBL} (user_id, character_name, character_name_key, month, day, image_url, updated_at)
          VALUES ($1,$2,$3,$4,$5,$6, now())
          ON CONFLICT (user_id, character_name_key)
          DO UPDATE SET
            character_name = EXCLUDED.character_name,
            month = EXCLUDED.month,
            day = EXCLUDED.day,
            image_url = EXCLUDED.image_url,
            updated_at = now()
          `,
          [r.user_id, r.character_name, r.character_name_key, r.month, r.day, r.image_url]
        );
        imported += 1;
      }

      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }

    res.setHeader("content-type", "text/html; charset=utf-8");
    res.send(
      renderPage({
        title: "Import complete",
        user: req.session.user,
        bodyHtml: `
          <div class="card">
            <div class="card-title">Import complete</div>
            <div>Imported/updated rows: <b>${imported}</b></div>
            <div class="spacer"></div>
            <div class="grid">
              <a class="btn primary" href="/admin/birthdays">Back to Admin Birthdays</a>
              <a class="btn" href="/admin/export.json" target="_blank" rel="noreferrer">Export now</a>
            </div>
          </div>
        `,
      })
    );
  } catch (e) {
    console.error("[IMPORT] error:", e);
    res.status(500).send(`Import failed: ${escapeHtml(e.message || String(e))}`);
  }
});

// ---------------- Start ----------------
app.listen(PORT, () => {
  console.log(`[WEB] listening on :${PORT}`);
  console.log(`[WEB] birthdays table: ${BIRTHDAYS_TABLE} (quoted as ${TBL})`);
  console.log(`[WEB] admin role ids: ${ADMIN_ROLE_IDS.length ? ADMIN_ROLE_IDS.join(",") : "(none set)"}`);
});
