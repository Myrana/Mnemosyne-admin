/**
 * index.js — Mnemosyne Admin (Railway) — full working file
 *
 * Fixes:
 * - No res.render / no views directory required
 * - Railway/proxy-safe sessions (trust proxy + secure cookies)
 * - Discord OAuth works without login loop (req.session.save before redirect)
 * - Postgres-backed sessions via connect-pg-simple with auto table creation
 * - Basic CRUD endpoints for birthdays (user + admin)
 *
 * ENV REQUIRED:
 *   DATABASE_URL
 *   DISCORD_CLIENT_ID
 *   DISCORD_CLIENT_SECRET
 *   DISCORD_REDIRECT_URI          e.g. https://YOUR-SERVICE.up.railway.app/callback
 *   DISCORD_GUILD_ID
 *   SESSION_SECRET
 *
 * OPTIONAL:
 *   ALLOWED_ROLE_IDS              comma-separated role IDs that count as admin (or empty = no role admin)
 *   PORT                          defaults 3000
 *
 * DB TABLE EXPECTED:
 *   "Birthdays" (capital B)  OR set BIRTHDAYS_TABLE to the exact name.
 *
 * Columns expected:
 *   id (serial/bigserial primary key)   [optional if you use (user_id, character_name) unique]
 *   user_id text or bigint
 *   character_name text
 *   month int
 *   day int
 *   image_url text
 *
 * If your table name is different:
 *   set env BIRTHDAYS_TABLE=Birthdays
 */

import express from "express";
import session from "express-session";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import crypto from "crypto";

const { Pool } = pg;
const PgSession = connectPgSimple(session);

const app = express();

// ---------- Env helpers ----------
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
const SESSION_SECRET = requireEnv("SESSION_SECRET");

const BIRTHDAYS_TABLE = process.env.BIRTHDAYS_TABLE || "birthdays";

// Admin roles allowed to use /admin routes (comma-separated role IDs)
const ADMIN_ROLE_IDS = (process.env.ADMIN_ROLE_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ---------- Postgres ----------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : undefined,
});

// ---------- App middleware ----------
app.set("trust proxy", 1); // IMPORTANT for Railway HTTPS + secure cookies

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Postgres-backed sessions (fixes redirect loop + survives restarts)
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
      secure: true, // Railway uses HTTPS
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// ---------- Utilities ----------
function escapeHtml(s = "") {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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
  return /^(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(mmdd);
}

function cleanName(name) {
  return String(name || "").replace(/\s+/g, " ").trim();
}

function tableIdent(name) {
  // Safe-ish identifier quoting (prevents casing issues & injection via env)
  // Only allow letters/numbers/underscore, otherwise error.
  if (!/^[A-Za-z0-9_]+$/.test(name)) {
    throw new Error(`Unsafe table name: ${name}`);
  }
  return `"${name}"`;
}

const TBL = tableIdent(BIRTHDAYS_TABLE);

// ---------- Schema ensure ----------
async function ensureSchema() {
  // Ensure a dedupe table for "already shouted today" checks if you want it later.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS birthday_shouts (
      shout_date date NOT NULL,
      user_id text NOT NULL,
      character_name_key text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (shout_date, user_id, character_name_key)
    );
  `);

  // Ensure birthdays table exists (optional; if you already made it, this will not harm)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${TBL} (
      id SERIAL PRIMARY KEY,
      user_id text NOT NULL,
      character_name text NOT NULL,
      month integer NOT NULL CHECK (month BETWEEN 1 AND 12),
      day integer NOT NULL CHECK (day BETWEEN 1 AND 31),
      image_url text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  // Recommended uniqueness: per-user + case-insensitive character name
  // (prevents duplicates like "Cash Langston" vs "cash langston")
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS birthdays_user_char_unique
    ON ${TBL} (user_id, lower(character_name));
  `);
}

// Run once on boot
ensureSchema().catch((e) => {
  console.error("[BOOT] schema ensure failed:", e);
  process.exit(1);
});

// ---------- Discord OAuth helpers ----------
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
  if (!r.ok) {
    throw new Error(`Token exchange failed: ${r.status} ${text}`);
  }
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
  // Requires Bot Token to read guild member roles.
  // Use your BOT TOKEN here (not client secret).
  // Put it in env BOT_TOKEN.
  const BOT_TOKEN = requireEnv("BOT_TOKEN");

  const r = await fetch(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`, {
    headers: { Authorization: `Bot ${BOT_TOKEN}` },
  });

  const text = await r.text();
  if (!r.ok) {
    // If the user isn't in the server, this will fail; treat as no roles.
    console.warn("[DISCORD] member lookup failed:", r.status, text);
    return [];
  }
  const member = JSON.parse(text);
  return Array.isArray(member.roles) ? member.roles : [];
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  const user = req.session.user || null;

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <title>Mnemosyne Admin</title>
      </head>
      <body style="font-family: system-ui; padding: 24px;">
        <h1>Mnemosyne Admin</h1>

        ${user ? `
          <p>Logged in as <b>${escapeHtml(user.username)}</b> ${user.is_admin ? "(admin)" : ""}</p>
          <ul>
            <li><a href="/me/birthdays">My birthdays</a></li>
            ${user.is_admin ? `<li><a href="/admin/birthdays">Admin: all birthdays</a></li>` : ""}
            <li><a href="/logout">Logout</a></li>
          </ul>
        ` : `
          <p>You are not logged in.</p>
          <p><a href="/login">Login with Discord</a></p>
        `}

        <hr/>
        <p><a href="/health">Health</a></p>
      </body>
    </html>
  `);
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Discord OAuth start
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

  // Save session before redirect (helps in some proxy setups)
  req.session.save((err) => {
    if (err) console.error("[SESSION] save before login redirect failed:", err);
    res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
  });
});

// Discord OAuth callback
app.get("/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state;

    if (!code) return res.status(400).send("Missing ?code");
    if (!state || state !== req.session.oauth_state) {
      return res.status(400).send("OAuth state mismatch. Please try /login again.");
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

    // ✅ IMPORTANT: persist session before redirect (prevents login loop)
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

// ---------- Birthdays UI (simple HTML forms) ----------
// Per-user view/add/edit/delete (only your own)
app.get("/me/birthdays", mustBeAuthed, async (req, res) => {
  const userId = String(req.session.user.id);

  const { rows } = await pool.query(
    `SELECT id, character_name, month, day, image_url
     FROM ${TBL}
     WHERE user_id=$1
     ORDER BY month ASC, day ASC, lower(character_name) ASC`,
    [userId]
  );

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>My Birthdays</title></head>
      <body style="font-family: system-ui; padding: 24px;">
        <p><a href="/">← Home</a></p>
        <h2>My Birthdays</h2>

        <h3>Add</h3>
        <form method="POST" action="/me/birthdays">
          <div><label>Character Name<br/><input name="character_name" required style="width: 360px"/></label></div>
          <div><label>Date (MM-DD)<br/><input name="mmdd" placeholder="07-12" required style="width: 120px"/></label></div>
          <div><label>Image URL<br/><input name="image_url" style="width: 560px"/></label></div>
          <button type="submit">Add</button>
        </form>

        <hr/>

        <h3>List</h3>
        ${rows.length ? `
          <table border="1" cellpadding="8" cellspacing="0">
            <thead><tr><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows.map(r => `
                <tr>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td>${String(r.month).padStart(2,"0")}-${String(r.day).padStart(2,"0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank">link</a>` : ""}</td>
                  <td>
                    <form method="POST" action="/me/birthdays/${r.id}/delete" style="display:inline;">
                      <button type="submit" onclick="return confirm('Delete this birthday?')">Delete</button>
                    </form>
                    <details style="display:inline-block; margin-left: 8px;">
                      <summary>Edit</summary>
                      <form method="POST" action="/me/birthdays/${r.id}/edit">
                        <div><label>Name<br/><input name="character_name" value="${escapeHtml(r.character_name)}" required/></label></div>
                        <div><label>MM-DD<br/><input name="mmdd" value="${String(r.month).padStart(2,"0")}-${String(r.day).padStart(2,"0")}" required/></label></div>
                        <div><label>Image URL<br/><input name="image_url" value="${escapeHtml(r.image_url || "")}" style="width: 460px"/></label></div>
                        <button type="submit">Save</button>
                      </form>
                    </details>
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        ` : `<p>No birthdays yet.</p>`}
      </body>
    </html>
  `);
});

app.post("/me/birthdays", mustBeAuthed, async (req, res) => {
  try {
    const userId = String(req.session.user.id);

    const character_name = cleanName(req.body.character_name);
    const mmdd = String(req.body.mmdd || "");
    const image_url = cleanName(req.body.image_url || "");

    if (!character_name) return res.status(400).send("Missing character_name");
    if (!mmddValid(mmdd)) return res.status(400).send("Invalid mmdd (use MM-DD)");

    const [m, d] = mmdd.split("-").map((x) => Number(x));

    // ✅ DEFINE THIS (this is what your error is complaining about)
    const character_name_key = cleanName(character_name).toLowerCase();

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
    console.error("[ADD] failed:", e);
    res.status(500).send(`Add failed: ${e.message}`);
  }
});



app.post("/me/birthdays/:id/edit", mustBeAuthed, async (req, res) => {
  const userId = String(req.session.user.id);
  const id = Number(req.params.id);

  const character_name = cleanName(req.body.character_name);
  const mmdd = String(req.body.mmdd || "");
  const image_url = cleanName(req.body.image_url || "");

  if (!id) return res.status(400).send("Bad id");
  if (!character_name) return res.status(400).send("Missing character_name");
  if (!mmddValid(mmdd)) return res.status(400).send("Invalid mmdd (use MM-DD)");

  const [m, d] = mmdd.split("-").map((x) => Number(x));

  // Ensure you can only edit your own row
  await pool.query(
    `
    UPDATE ${TBL}
    SET character_name=$1, month=$2, day=$3, image_url=NULLIF($4,''), updated_at=now()
    WHERE id=$5 AND user_id=$6
    `,
    [character_name, m, d, image_url, id, userId]
  );

  res.redirect("/me/birthdays");
});

app.post("/me/birthdays/:id/delete", mustBeAuthed, async (req, res) => {
  const userId = String(req.session.user.id);
  const id = Number(req.params.id);

  if (!id) return res.status(400).send("Bad id");

  await pool.query(`DELETE FROM ${TBL} WHERE id=$1 AND user_id=$2`, [id, userId]);

  res.redirect("/me/birthdays");
});

// ---------- Admin-only view (all birthdays) ----------
app.get("/admin/birthdays", mustBeAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, user_id, character_name, month, day, image_url
     FROM ${TBL}
     ORDER BY month ASC, day ASC, lower(character_name) ASC`
  );

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Admin Birthdays</title></head>
      <body style="font-family: system-ui; padding: 24px;">
        <p><a href="/">← Home</a></p>
        <h2>Admin: All Birthdays</h2>
        <p>Total: ${rows.length}</p>
        ${rows.length ? `
          <table border="1" cellpadding="8" cellspacing="0">
            <thead><tr><th>User ID</th><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows.map(r => `
                <tr>
                  <td>${escapeHtml(r.user_id)}</td>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td>${String(r.month).padStart(2,"0")}-${String(r.day).padStart(2,"0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank">link</a>` : ""}</td>
                  <td>
                    <form method="POST" action="/admin/birthdays/${r.id}/delete" style="display:inline;">
                      <button type="submit" onclick="return confirm('Admin delete this birthday?')">Delete</button>
                    </form>
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        ` : `<p>No rows.</p>`}
      </body>
    </html>
  `);
});

app.post("/admin/birthdays/:id/delete", mustBeAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).send("Bad id");

  await pool.query(`DELETE FROM ${TBL} WHERE id=$1`, [id]);
  res.redirect("/admin/birthdays");
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`[WEB] listening on :${PORT}`);
  console.log(`[WEB] birthdays table env BIRTHDAYS_TABLE=${BIRTHDAYS_TABLE} (quoted as ${TBL})`);
});


