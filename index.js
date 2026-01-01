/**
 * index.js — Mnemosyne Web Admin (Railway) — FULL FILE
 *
 * What this version fixes/does:
 * ✅ Works with table name: birthdays (lowercase)
 * ✅ Supports a NOT NULL character_name_key column (auto-computed)
 * ✅ Prevents duplicates via UNIQUE(user_id, character_name_key)
 * ✅ Discord OAuth without login loop (Postgres sessions + req.session.save)
 * ✅ Admin-only routes via ADMIN_ROLE_IDS (not your member id)
 * ✅ Per-user view/add/edit/delete
 * ✅ Admin view + search by username/global_name/user_id/character
 * ✅ Admin can add birthdays for ANY user (by searching users table)
 *
 * REQUIRED ENV:
 *  DATABASE_URL
 *  DISCORD_CLIENT_ID
 *  DISCORD_CLIENT_SECRET
 *  DISCORD_REDIRECT_URI        e.g. https://YOURAPP.up.railway.app/callback
 *  DISCORD_GUILD_ID
 *  BOT_TOKEN                  (your Discord BOT token, used for member roles)
 *  SESSION_SECRET
 *
 * OPTIONAL ENV:
 *  ADMIN_ROLE_IDS             comma-separated role IDs (Discord role IDs) that count as admin
 *  BIRTHDAYS_TABLE            defaults to "birthdays"
 *  PORT                       defaults 3000
 *
 * Notes:
 * - This file creates/ensures tables: users, web_sessions, birthday_shouts, birthdays (if missing)
 * - If you already created birthdays in UI, it will not destroy data.
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
const BOT_TOKEN = requireEnv("BOT_TOKEN");
const SESSION_SECRET = requireEnv("SESSION_SECRET");

const BIRTHDAYS_TABLE = process.env.BIRTHDAYS_TABLE || "birthdays";

// Admin role IDs (Discord role IDs, comma-separated)
const ADMIN_ROLE_IDS = (process.env.ADMIN_ROLE_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ---------- Postgres ----------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : undefined,
});

// ---------- Middleware ----------
app.set("trust proxy", 1); // Railway HTTPS proxy

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Postgres-backed sessions
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
      secure: true, // Railway is HTTPS
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
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

function cleanName(name) {
  return String(name || "").replace(/\s+/g, " ").trim();
}

// IMPORTANT: this matches the not-null column that bit you
function characterNameKey(name) {
  return cleanName(name).toLowerCase();
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

function tableIdent(name) {
  // allow letters numbers underscore ONLY
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(`Unsafe table name: ${name}`);
  return `"${name}"`;
}

const TBL = tableIdent(BIRTHDAYS_TABLE);

// ---------- Schema ensure ----------
async function ensureSchema() {
  // users table for username search + admin add-by-search
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      username TEXT,
      discriminator TEXT,
      global_name TEXT,
      avatar TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_username_idx ON users (lower(username));`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_global_name_idx ON users (lower(global_name));`);

  // shout dedupe table (optional but good)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS birthday_shouts (
      shout_date date NOT NULL,
      user_id text NOT NULL,
      character_name_key text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (shout_date, user_id, character_name_key)
    );
  `);

  // birthdays table — includes character_name_key NOT NULL (this fixes your errors)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${TBL} (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      character_name TEXT NOT NULL,
      character_name_key TEXT NOT NULL,
      month INTEGER NOT NULL CHECK (month BETWEEN 1 AND 12),
      day INTEGER NOT NULL CHECK (day BETWEEN 1 AND 31),
      image_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // If your table already existed but was missing the key column, add it.
  // If it already exists, harmless.
  await pool.query(`
    ALTER TABLE ${TBL}
    ADD COLUMN IF NOT EXISTS character_name_key TEXT;
  `);

  // backfill NULL keys if needed
  await pool.query(`
    UPDATE ${TBL}
    SET character_name_key = lower(trim(regexp_replace(character_name, '\\s+', ' ', 'g')))
    WHERE character_name_key IS NULL;
  `);

  // enforce NOT NULL (only after backfill)
  await pool.query(`
    ALTER TABLE ${TBL}
    ALTER COLUMN character_name_key SET NOT NULL;
  `);

  // Unique dedupe: one per user + character_name_key
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS birthdays_user_char_key_unique
    ON ${TBL} (user_id, character_name_key);
  `);

  // helpful index for admin ordering/search
  await pool.query(`
    CREATE INDEX IF NOT EXISTS birthdays_month_day_idx
    ON ${TBL} (month, day);
  `);
}

// boot
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
  const r = await fetch(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`, {
    headers: { Authorization: `Bot ${BOT_TOKEN}` },
  });
  const text = await r.text();
  if (!r.ok) {
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
      <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Mnemosyne Admin</title></head>
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
    res.json({ ok: true, table: BIRTHDAYS_TABLE });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e), table: BIRTHDAYS_TABLE });
  }
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
      return res.status(400).send("OAuth state mismatch. Please try /login again.");
    }

    const token = await discordTokenExchange(code);
    const user = await discordGetUser(token.access_token);
    const roles = await discordGetMemberRoles(user.id);

    // store user for searching later
    await pool.query(
      `
      INSERT INTO users (user_id, username, discriminator, global_name, avatar, updated_at)
      VALUES ($1, $2, $3, $4, $5, now())
      ON CONFLICT (user_id)
      DO UPDATE SET
        username=EXCLUDED.username,
        discriminator=EXCLUDED.discriminator,
        global_name=EXCLUDED.global_name,
        avatar=EXCLUDED.avatar,
        updated_at=now()
      `,
      [
        String(user.id),
        user.username || null,
        user.discriminator || null,
        user.global_name || null,
        user.avatar || null,
      ]
    );

    req.session.user = {
      id: String(user.id),
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

// ---------- Per-user birthdays ----------
app.get("/me/birthdays", mustBeAuthed, async (req, res) => {
  const userId = String(req.session.user.id);

  const { rows } = await pool.query(
    `SELECT id, character_name, month, day, image_url
     FROM ${TBL}
     WHERE user_id=$1
     ORDER BY month ASC, day ASC, character_name_key ASC`,
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
    const key = characterNameKey(character_name);

    // ✅ THIS is what fixes your NOT NULL character_name_key issue
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
      [userId, character_name, key, m, d, image_url]
    );

    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[ADD me] failed:", e);
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

    const [m, d] = mmdd.split("-").map((x) => Number(x));
    const key = characterNameKey(character_name);

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
      [character_name, key, m, d, image_url, id, userId]
    );

    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[EDIT me] failed:", e);
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
    console.error("[DEL me] failed:", e);
    res.status(500).send(`Delete failed: ${escapeHtml(e.message)}`);
  }
});

// ---------- Admin: search users + add birthdays for other people ----------
app.get("/admin/birthdays", mustBeAdmin, async (req, res) => {
  const q = String(req.query.q || "").trim();
  const uq = String(req.query.uq || "").trim(); // user search

  // birthdays list
  let birthdayRows = [];
  if (!q) {
    ({ rows: birthdayRows } = await pool.query(
      `
      SELECT b.id, b.user_id, b.character_name, b.month, b.day, b.image_url,
             u.username, u.global_name
      FROM ${TBL} b
      LEFT JOIN users u ON u.user_id = b.user_id
      ORDER BY b.month ASC, b.day ASC, b.character_name_key ASC
      `
    ));
  } else {
    ({ rows: birthdayRows } = await pool.query(
      `
      SELECT b.id, b.user_id, b.character_name, b.month, b.day, b.image_url,
             u.username, u.global_name
      FROM ${TBL} b
      LEFT JOIN users u ON u.user_id = b.user_id
      WHERE
        b.character_name ILIKE $1
        OR b.user_id = $2
        OR u.username ILIKE $1
        OR u.global_name ILIKE $1
      ORDER BY b.month ASC, b.day ASC, b.character_name_key ASC
      `,
      [`%${q}%`, q]
    ));
  }

  // user search results for admin-add form
  let userRows = [];
  if (uq) {
    ({ rows: userRows } = await pool.query(
      `
      SELECT user_id, username, global_name
      FROM users
      WHERE
        user_id = $1
        OR username ILIKE $2
        OR global_name ILIKE $2
      ORDER BY lower(coalesce(global_name, username, user_id)) ASC
      LIMIT 25
      `,
      [uq, `%${uq}%`]
    ));
  }

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Admin Birthdays</title></head>
      <body style="font-family: system-ui; padding: 24px;">
        <p><a href="/">← Home</a></p>
        <h2>Admin: All Birthdays</h2>

        <h3>Search birthdays</h3>
        <form method="GET" action="/admin/birthdays" style="margin: 12px 0;">
          <input name="q" placeholder="Search character / username / user_id" value="${escapeHtml(q)}" style="width:360px;">
          <button type="submit">Search</button>
          <a href="/admin/birthdays" style="margin-left:8px;">Clear</a>
        </form>

        <hr/>

        <h3>Admin Add (for any user)</h3>
        <form method="GET" action="/admin/birthdays" style="margin: 12px 0;">
          <input name="uq" placeholder="Find user (username / global name / user_id)" value="${escapeHtml(uq)}" style="width:360px;">
          ${q ? `<input type="hidden" name="q" value="${escapeHtml(q)}">` : ""}
          <button type="submit">Find</button>
        </form>

        ${uq ? `
          <form method="POST" action="/admin/birthdays/add" style="border:1px solid #ccc; padding:12px; max-width: 760px;">
            <div>
              <label>User
                <br/>
                <select name="target_user_id" required style="width: 520px;">
                  <option value="">-- pick a user --</option>
                  ${userRows.map(u => `
                    <option value="${escapeHtml(u.user_id)}">
                      ${escapeHtml(u.global_name || u.username || u.user_id)} (${escapeHtml(u.user_id)})
                    </option>
                  `).join("")}
                </select>
              </label>
            </div>
            <div style="margin-top:8px;">
              <label>Character Name<br/><input name="character_name" required style="width: 360px"/></label>
            </div>
            <div style="margin-top:8px;">
              <label>Date (MM-DD)<br/><input name="mmdd" placeholder="07-12" required style="width: 120px"/></label>
            </div>
            <div style="margin-top:8px;">
              <label>Image URL<br/><input name="image_url" style="width: 560px"/></label>
            </div>
            <button type="submit" style="margin-top:10px;">Add for user</button>
          </form>
        ` : `<p style="color:#666;">Search a user above to enable the admin add form.</p>`}

        <hr/>

        <h3>All birthdays (${birthdayRows.length})</h3>
        ${birthdayRows.length ? `
          <table border="1" cellpadding="8" cellspacing="0">
            <thead><tr><th>User</th><th>User ID</th><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${birthdayRows.map(r => `
                <tr>
                  <td>${escapeHtml(r.global_name || r.username || "(unknown)")}</td>
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

app.post("/admin/birthdays/add", mustBeAdmin, async (req, res) => {
  try {
    const targetUserId = String(req.body.target_user_id || "").trim();
    const character_name = cleanName(req.body.character_name);
    const mmdd = String(req.body.mmdd || "");
    const image_url = cleanName(req.body.image_url || "");

    if (!targetUserId) return res.status(400).send("Missing target_user_id");
    if (!character_name) return res.status(400).send("Missing character_name");
    if (!mmddValid(mmdd)) return res.status(400).send("Invalid mmdd (use MM-DD)");

    const [m, d] = mmdd.split("-").map((x) => Number(x));
    const key = characterNameKey(character_name);

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
      [targetUserId, character_name, key, m, d, image_url]
    );

    res.redirect("/admin/birthdays?uq=" + encodeURIComponent(targetUserId));
  } catch (e) {
    console.error("[ADMIN ADD] failed:", e);
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
    console.error("[ADMIN DEL] failed:", e);
    res.status(500).send(`Admin delete failed: ${escapeHtml(e.message)}`);
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`[WEB] listening on :${PORT}`);
  console.log(`[WEB] table = ${BIRTHDAYS_TABLE} (quoted ${TBL})`);
  console.log(`[WEB] admin roles configured = ${ADMIN_ROLE_IDS.length ? ADMIN_ROLE_IDS.join(",") : "(none)"}`);
});


