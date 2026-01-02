/**
 * index.js — Mnemosyne Admin (Railway) — FULL FILE (Option B)
 *
 * Features:
 * - Discord OAuth login (no redirect loop)
 * - Postgres-backed sessions (connect-pg-simple) with auto table creation
 * - Birthdays CRUD
 *   - /me/birthdays : user view/add/edit/delete (only their own rows)
 *   - /admin/birthdays : admin view + admin add for ANY Discord user ID (Option B) + admin delete
 *   - /admin/search : admin search by user_id or character_name
 * - Admin backup/restore
 *   - /admin/export.json : download JSON
 *   - /admin/import      : paste JSON to upsert rows back in
 * - UI:
 *   - Light/Dark/Auto theme toggle (localStorage)
 *   - Admin links shown ONLY in Admin Tools card (no duplicates)
 *
 * ENV REQUIRED:
 *   DATABASE_URL
 *   DISCORD_CLIENT_ID
 *   DISCORD_CLIENT_SECRET
 *   DISCORD_REDIRECT_URI     e.g. https://YOUR-SERVICE.up.railway.app/callback
 *   DISCORD_GUILD_ID
 *   BOT_TOKEN               (Discord bot token; used to look up guild member roles)
 *   SESSION_SECRET
 *
 * OPTIONAL:
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
app.set("trust proxy", 1);
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
      secure: true,
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

function tableIdent(name) {
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(`Unsafe table name: ${name}`);
  return `"${name}"`;
}

const TBL = tableIdent(BIRTHDAYS_TABLE);

// ---------------- UI helpers (theme + shell) ----------------
function baseCss() {
  return `
  <style>
    :root{
      color-scheme: light dark;
      --bg: #ffffff;
      --fg: #111111;
      --muted: #555;
      --card: #f6f6f6;
      --border: #dddddd;
      --link: #1a73e8;
      --btn-bg: #111;
      --btn-fg: #fff;
      --input-bg: #fff;
      --input-fg: #111;
      --danger: #c62828;
    }
    @media (prefers-color-scheme: dark){
      :root{
        --bg: #0b0d10;
        --fg: #e8e8e8;
        --muted: #b4b4b4;
        --card: #11141a;
        --border: #2a2f3a;
        --link: #8ab4f8;
        --btn-bg: #e8e8e8;
        --btn-fg: #0b0d10;
        --input-bg: #0f131a;
        --input-fg: #e8e8e8;
        --danger: #ff6b6b;
      }
    }
    html[data-theme="light"]{
      --bg: #ffffff;
      --fg: #111111;
      --muted: #555;
      --card: #f6f6f6;
      --border: #dddddd;
      --link: #1a73e8;
      --btn-bg: #111;
      --btn-fg: #fff;
      --input-bg: #fff;
      --input-fg: #111;
      --danger: #c62828;
    }
    html[data-theme="dark"]{
      --bg: #0b0d10;
      --fg: #e8e8e8;
      --muted: #b4b4b4;
      --card: #11141a;
      --border: #2a2f3a;
      --link: #8ab4f8;
      --btn-bg: #e8e8e8;
      --btn-fg: #0b0d10;
      --input-bg: #0f131a;
      --input-fg: #e8e8e8;
      --danger: #ff6b6b;
    }

    body{
      background: var(--bg);
      color: var(--fg);
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      padding: 24px;
      margin: 0;
      line-height: 1.35;
    }

    a{ color: var(--link); }
    hr{ border: 0; border-top: 1px solid var(--border); margin: 16px 0; }

    .row{ display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    .muted{ color: var(--muted); }
    .small{ font-size: 0.95rem; }
    .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }

    .card{
      border: 1px solid var(--border);
      background: var(--card);
      border-radius: 12px;
      padding: 12px;
      margin: 12px 0;
    }

    .btn{
      background: var(--btn-bg);
      color: var(--btn-fg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px 12px;
      cursor: pointer;
      font-weight: 600;
    }

    .btn.danger{
      border-color: var(--danger);
    }

    input, textarea{
      background: var(--input-bg);
      color: var(--input-fg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 10px;
      outline: none;
    }

    table{
      border-collapse: collapse;
      width: 100%;
      max-width: 1100px;
    }
    th, td{
      border: 1px solid var(--border);
      padding: 8px;
      text-align: left;
      vertical-align: top;
    }
    th{ background: color-mix(in oklab, var(--card) 85%, var(--bg)); }

    .links{ display:flex; gap:12px; flex-wrap:wrap; margin-top:8px; }
    details summary{ cursor: pointer; font-weight: 600; }
  </style>
  `;
}

function themeToggleScript() {
  return `
  <script>
    (function(){
      const KEY = "mnemo_theme"; // "light" | "dark" | null(auto)
      const saved = localStorage.getItem(KEY);
      if (saved === "light" || saved === "dark") {
        document.documentElement.setAttribute("data-theme", saved);
      }
      window.__mnemoTheme = {
        get() { return document.documentElement.getAttribute("data-theme") || ""; },
        set(next) {
          if (next === "light" || next === "dark") {
            document.documentElement.setAttribute("data-theme", next);
            localStorage.setItem(KEY, next);
          } else {
            document.documentElement.removeAttribute("data-theme");
            localStorage.removeItem(KEY);
          }
        },
        cycle() {
          const cur = this.get(); // "" -> auto
          if (!cur) this.set("dark");
          else if (cur === "dark") this.set("light");
          else this.set(""); // back to auto
        }
      };
    })();
  </script>
  `;
}

function themeToggleButton() {
  return `
    <button class="btn" type="button" id="themeToggle"></button>
    <script>
      (function(){
        const btn = document.getElementById("themeToggle");
        if (!btn || !window.__mnemoTheme) return;

        function label(){
          const cur = window.__mnemoTheme.get();
          btn.textContent = cur ? ("Theme: " + cur + " (click)") : "Theme: auto (click)";
        }

        btn.addEventListener("click", function(){
          window.__mnemoTheme.cycle();
          label();
        });

        label();
      })();
    </script>
  `;
}

function adminToolsCard(user) {
  if (!user?.is_admin) return "";
  return `
    <div class="card">
      <b>Admin Tools</b>
      <div class="links">
        <a href="/admin/birthdays">All Birthdays</a>
        <a href="/admin/search">Search</a>
        <a href="/admin/export.json">Export JSON</a>
        <a href="/admin/import">Import JSON</a>
      </div>
    </div>
  `;
}

function renderPage({ title, user, bodyHtml }) {
  return `
  <!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>${escapeHtml(title || "Mnemosyne Portal")}</title>
      ${baseCss()}
      ${themeToggleScript()}
    </head>
    <body>
      <div class="row">
        <h1 style="margin:0;">${escapeHtml(title || "Mnemosyne Portal")}</h1>
        ${themeToggleButton()}
      </div>

      ${bodyHtml || ""}

      <hr/>
    </body>
  </html>
  `;
}

// ---------------- Schema ensure ----------------
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS birthday_shouts (
      shout_date date NOT NULL,
      user_id text NOT NULL,
      character_name_key text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (shout_date, user_id, character_name_key)
    );
  `);

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

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='${BIRTHDAYS_TABLE}' AND column_name='character_name_key'
      ) THEN
        ALTER TABLE ${TBL} ADD COLUMN character_name_key text;
      END IF;

      UPDATE ${TBL}
      SET character_name_key = lower(btrim(regexp_replace(coalesce(character_name,''), '\\s+', ' ', 'g')))
      WHERE character_name_key IS NULL OR btrim(character_name_key) = '';

      IF NOT EXISTS (
        SELECT 1 FROM ${TBL}
        WHERE character_name_key IS NULL OR btrim(character_name_key) = ''
      ) THEN
        ALTER TABLE ${TBL} ALTER COLUMN character_name_key SET NOT NULL;
      END IF;
    END $$;
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS birthdays_user_char_key_unique
    ON ${TBL} (user_id, character_name_key);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS birthdays_mmdd_idx
    ON ${TBL} (month, day);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS birthdays_user_id_idx
    ON ${TBL} (user_id);
  `);
}

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

// ---------------- Routes ----------------
app.get("/", (req, res) => {
  const user = req.session.user || null;

  const bodyHtml = user
    ? `
      <p class="muted" style="margin-top:8px;">
        Logged in as <b>${escapeHtml(user.username)}</b> ${user.is_admin ? "(admin)" : ""}
      </p>

      <div class="card">
        <b>Quick Links</b>
        <div class="links">
          <a href="/me/birthdays">My birthdays</a>
          <a href="/logout">Logout</a>
        </div>
      </div>

      ${adminToolsCard(user)}
    `
    : `
      <p class="muted">You are not logged in.</p>
      <div class="card">
        <a href="/login">Login with Discord</a>
      </div>
    `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Mnemosyne Portal", user, bodyHtml }));
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
    <p><a href="/">← Home</a></p>
    <p class="muted">Logged in as <b>${escapeHtml(user.username)}</b>${user.is_admin ? " (admin)" : ""}</p>

    <div class="card">
      <b>Add birthday</b>
      <form method="POST" action="/me/birthdays" style="margin-top:10px;">
        <div style="margin: 8px 0;">
          <label>Character Name<br/>
            <input name="character_name" required style="width: min(520px, 95vw)"/>
          </label>
        </div>
        <div style="margin: 8px 0;">
          <label>Date (MM-DD)<br/>
            <input name="mmdd" placeholder="07-12" required style="width: 140px"/>
          </label>
        </div>
        <div style="margin: 8px 0;">
          <label>Image URL (optional)<br/>
            <input name="image_url" style="width: min(820px, 95vw)"/>
          </label>
        </div>
        <button class="btn" type="submit">Add</button>
      </form>
    </div>

    ${
      rows.length
        ? `
      <div class="card">
        <b>My saved birthdays</b>
        <div style="margin-top:10px; overflow:auto;">
          <table>
            <thead><tr><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td class="mono">${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank" rel="noreferrer">link</a>` : ""}</td>
                  <td>
                    <form method="POST" action="/me/birthdays/${r.id}/delete" style="display:inline;">
                      <button class="btn danger" type="submit" onclick="return confirm('Delete this birthday?')">Delete</button>
                    </form>
                    <details style="display:inline-block; margin-left: 10px;">
                      <summary>Edit</summary>
                      <form method="POST" action="/me/birthdays/${r.id}/edit" style="margin-top:8px;">
                        <div style="margin: 6px 0;">
                          <label>Name<br/>
                            <input name="character_name" value="${escapeHtml(r.character_name)}" required style="width: 320px"/>
                          </label>
                        </div>
                        <div style="margin: 6px 0;">
                          <label>MM-DD<br/>
                            <input name="mmdd" value="${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}" required style="width: 140px"/>
                          </label>
                        </div>
                        <div style="margin: 6px 0;">
                          <label>Image URL<br/>
                            <input name="image_url" value="${escapeHtml(r.image_url || "")}" style="width: min(720px, 95vw)"/>
                          </label>
                        </div>
                        <button class="btn" type="submit">Save</button>
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
      </div>
    `
        : `<div class="card"><b>No birthdays yet.</b> Add one above.</div>`
    }

    ${adminToolsCard(user)}
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

// ---------------- Admin: all birthdays + add (Option B) ----------------
app.get("/admin/birthdays", mustBeAdmin, async (req, res) => {
  const user = req.session.user;

  const { rows } = await pool.query(
    `SELECT id, user_id, character_name, month, day, image_url
     FROM ${TBL}
     ORDER BY month ASC, day ASC, character_name_key ASC`
  );

  const bodyHtml = `
    <p><a href="/">← Home</a></p>
    <p class="muted">Logged in as <b>${escapeHtml(user.username)}</b> (admin)</p>

    ${adminToolsCard(user)}

    <div class="card">
      <b>Admin Add (raw Discord user ID)</b>
      <form method="POST" action="/admin/birthdays/add" style="margin-top:10px;">
        <div style="margin: 8px 0;">
          <label>Discord User ID<br/>
            <input name="user_id" required style="width: min(520px, 95vw)"/>
          </label>
        </div>
        <div style="margin: 8px 0;">
          <label>Character Name<br/>
            <input name="character_name" required style="width: min(520px, 95vw)"/>
          </label>
        </div>
        <div style="margin: 8px 0;">
          <label>Date (MM-DD)<br/>
            <input name="mmdd" placeholder="07-12" required style="width: 140px"/>
          </label>
        </div>
        <div style="margin: 8px 0;">
          <label>Image URL (optional)<br/>
            <input name="image_url" style="width: min(820px, 95vw)"/>
          </label>
        </div>
        <button class="btn" type="submit">Add for user</button>
      </form>
    </div>

    <div class="card">
      <b>All birthdays</b>
      <div class="muted small" style="margin-top:6px;">Total rows: <b>${rows.length}</b></div>
      <div style="margin-top:10px; overflow:auto;">
        ${
          rows.length
            ? `
          <table>
            <thead><tr><th>User ID</th><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td class="mono">${escapeHtml(r.user_id)}</td>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td class="mono">${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank" rel="noreferrer">link</a>` : ""}</td>
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
        `
            : `<p class="muted">No rows.</p>`
        }
      </div>
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Admin: All Birthdays", user, bodyHtml }));
});

app.post("/admin/birthdays/add", mustBeAdmin, async (req, res) => {
  try {
    const targetUserId = String(req.body.user_id || "").trim();
    const character_name = cleanName(req.body.character_name);
    const mmdd = String(req.body.mmdd || "");
    const image_url = cleanName(req.body.image_url || "");

    if (!targetUserId) return res.status(400).send("Missing user_id");
    if (!/^\d{15,25}$/.test(targetUserId))
      return res.status(400).send("user_id should be a Discord numeric ID");
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

    res.redirect("/admin/birthdays");
  } catch (e) {
    console.error("[ADMIN ADD] error:", e);
    res.status(500).send(`Admin add failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/admin/birthdays/:id/delete", mustBeAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send("Bad id");

    await pool.query(`DELETE FROM ${TBL} WHERE id=$1`, [id]);
    res.redirect("/admin/birthdays");
  } catch (e) {
    console.error("[ADMIN DEL] error:", e);
    res.status(500).send(`Admin delete failed: ${escapeHtml(e.message)}`);
  }
});

// ---------------- Admin search ----------------
app.get("/admin/search", mustBeAdmin, async (req, res) => {
  const user = req.session.user;
  const q = String(req.query.q || "").trim();
  let rows = [];

  if (q) {
    if (/^\d{15,25}$/.test(q)) {
      const r = await pool.query(
        `SELECT id, user_id, character_name, month, day, image_url
         FROM ${TBL}
         WHERE user_id=$1
         ORDER BY month ASC, day ASC, character_name_key ASC`,
        [q]
      );
      rows = r.rows;
    } else {
      const r = await pool.query(
        `SELECT id, user_id, character_name, month, day, image_url
         FROM ${TBL}
         WHERE character_name ILIKE $1
         ORDER BY month ASC, day ASC, character_name_key ASC
         LIMIT 200`,
        [`%${q}%`]
      );
      rows = r.rows;
    }
  }

  const bodyHtml = `
    <p><a href="/">← Home</a></p>
    <p class="muted">Logged in as <b>${escapeHtml(user.username)}</b> (admin)</p>

    ${adminToolsCard(user)}

    <div class="card">
      <b>Search</b>
      <form method="GET" action="/admin/search" style="margin-top:10px;">
        <div>
          <label>Discord user id OR character name</label><br/>
          <input name="q" value="${escapeHtml(q)}" style="width: min(520px, 95vw)"/>
          <button class="btn" type="submit" style="margin-left:8px;">Search</button>
        </div>
      </form>
    </div>

    <div class="card">
      <b>Results</b>
      ${
        q
          ? `<div class="muted small" style="margin-top:6px;">Results for <b>${escapeHtml(
              q
            )}</b>: ${rows.length}</div>`
          : `<div class="muted small" style="margin-top:6px;">Enter a user id (numbers) or a character name.</div>`
      }

      <div style="margin-top:10px; overflow:auto;">
        ${
          rows.length
            ? `
          <table>
            <thead><tr><th>User ID</th><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td class="mono">${escapeHtml(r.user_id)}</td>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td class="mono">${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank" rel="noreferrer">link</a>` : ""}</td>
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
        `
            : q
            ? `<p class="muted">No matches.</p>`
            : ``
        }
      </div>
    </div>
  `;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(renderPage({ title: "Admin: Search", user, bodyHtml }));
});

// ---------- Backup/Restore helpers ----------
function toCharKey(name) {
  return cleanName(name).toLowerCase();
}

function isRowFormat(obj) {
  return obj && typeof obj === "object" && "user_id" in obj && "character_name" in obj;
}

function isLegacyFormat(obj) {
  return obj && typeof obj === "object" && !Array.isArray(obj);
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
    character_name_key: toCharKey(character_name),
    month: m,
    day: d,
    image_url: image_url || null,
  };
}

// ---------- Admin JSON export ----------
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

// ---------- Admin import UI ----------
app.get("/admin/import", mustBeAdmin, async (req, res) => {
  const user = req.session.user;

  const bodyHtml = `
    <p><a href="/">← Home</a></p>
    <p class="muted">Logged in as <b>${escapeHtml(user.username)}</b> (admin)</p>

    ${adminToolsCard(user)}

    <div class="card">
      <b>Import JSON Backup</b>
      <p class="muted small" style="margin-top:6px;">
        This will <b>upsert</b> rows (insert new + update existing). It will not delete rows that aren’t in the import.
      </p>

      <form method="POST" action="/admin/import">
        <div style="margin-top:10px;">
          <label>Paste JSON here</label><br/>
          <textarea name="json" rows="18" style="width: min(920px, 95vw);" required></textarea>
        </div>

        <div style="margin-top: 12px;">
          <label>
            <input type="checkbox" name="confirm" value="yes" required/>
            I understand this will modify the database.
          </label>
        </div>

        <div style="margin-top: 12px;">
          <button class="btn" type="submit">Import</button>
        </div>
      </form>
    </div>

    <div class="card">
      <b>Supported formats</b>
      <pre style="white-space:pre-wrap;" class="small muted">
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
  res.send(renderPage({ title: "Admin: Import JSON", user, bodyHtml }));
});

// ---------- Admin import handler ----------
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
        const user_id = String(r.user_id);
        const character_name = cleanName(r.character_name);
        const character_name_key = cleanName(r.character_name_key || toCharKey(character_name));
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
        const user_id = String(r.user_id);
        const character_name = cleanName(r.character_name);
        const character_name_key = cleanName(r.character_name_key || toCharKey(character_name));
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
        if (!Array.isArray(list)) continue;
        for (const entry of list) {
          const parsed = parseLegacyEntry(entry);
          if (!parsed) continue;
          rowsToImport.push({ user_id: String(uid), ...parsed });
        }
      }
    } else {
      return res.status(400).send("Unrecognized JSON format.");
    }

    if (!rowsToImport.length) {
      return res.status(400).send("No valid rows found in JSON.");
    }

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
          <p><a href="/">← Home</a></p>
          ${adminToolsCard(req.session.user)}
          <div class="card">
            <b>Import complete</b>
            <p>Imported/updated rows: <b>${imported}</b></p>
            <p><a href="/admin/birthdays">Go to Admin: All Birthdays</a></p>
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


// ---------------- Start ----------------
app.listen(PORT, () => {
  console.log(`[WEB] listening on :${PORT}`);
  console.log(`[WEB] birthdays table: ${BIRTHDAYS_TABLE} (quoted as ${TBL})`);
  console.log(
    `[WEB] admin role ids: ${ADMIN_ROLE_IDS.length ? ADMIN_ROLE_IDS.join(",") : "(none set)"}`
  );
});
