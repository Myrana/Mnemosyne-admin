/**
 * index.js — Mnemosyne Admin (Railway) — FULL FILE (Option B)
 *
 * What this version does:
 * - Discord OAuth login (no redirect loop)
 * - Postgres-backed sessions (connect-pg-simple) with auto table creation
 * - Birthdays CRUD
 *   - /me/birthdays : user view/add/edit/delete (only their own rows)
 *   - /admin/birthdays : admin view + admin add for ANY Discord user ID (Option B) + admin delete
 *   - /admin/search : admin search by user_id or character_name
 *
 * IMPORTANT (your schema):
 * - Your "birthdays" table must have a NOT NULL "character_name_key".
 *   This file ensures the column exists and backfills it from character_name.
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

function tableIdent(name) {
  // allow only safe identifiers to avoid injection via env
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(`Unsafe table name: ${name}`);
  return `"${name}"`;
}

const TBL = tableIdent(BIRTHDAYS_TABLE);

// ---------------- Schema ensure ----------------
async function ensureSchema() {
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

  // 3) If table already existed without character_name_key, add it + backfill safely
  //    Also ensures NOT NULL (only after backfill).
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='${BIRTHDAYS_TABLE}' AND column_name='character_name_key'
      ) THEN
        ALTER TABLE ${TBL} ADD COLUMN character_name_key text;
      END IF;

      -- Backfill any null/blank keys from character_name
      UPDATE ${TBL}
      SET character_name_key = lower(btrim(regexp_replace(coalesce(character_name,''), '\\s+', ' ', 'g')))
      WHERE character_name_key IS NULL OR btrim(character_name_key) = '';

      -- If still any nulls, don't force NOT NULL (would fail). Otherwise enforce.
      IF NOT EXISTS (
        SELECT 1 FROM ${TBL}
        WHERE character_name_key IS NULL OR btrim(character_name_key) = ''
      ) THEN
        ALTER TABLE ${TBL} ALTER COLUMN character_name_key SET NOT NULL;
      END IF;
    END $$;
  `);

  // 4) Unique index to support ON CONFLICT (user_id, character_name_key)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS birthdays_user_char_key_unique
    ON ${TBL} (user_id, character_name_key);
  `);

  // 5) Helpful index for sorting/searching
  await pool.query(`
    CREATE INDEX IF NOT EXISTS birthdays_mmdd_idx
    ON ${TBL} (month, day);
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
    // if user isn't in server, treat as no roles
    console.warn("[DISCORD] member lookup failed:", r.status, text);
    return [];
  }

  const member = JSON.parse(text);
  return Array.isArray(member.roles) ? member.roles : [];
}

// ---------------- Routes ----------------
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

        ${
          user
            ? `
          <p>Logged in as <b>${escapeHtml(user.username)}</b> ${
                user.is_admin ? "(admin)" : ""
              }</p>
          <ul>
            <li><a href="/me/birthdays">My birthdays</a></li>
            ${
              user.is_admin
                ? `
              <li><a href="/admin/birthdays">Admin: all birthdays</a></li>
              <li><a href="/admin/search">Admin: search</a></li>
            `
                : ""
            }
            <li><a href="/logout">Logout</a></li>
          </ul>
        `
            : `
          <p>You are not logged in.</p>
          <p><a href="/login">Login with Discord</a></p>
        `
        }

        <hr/>
        <p><a href="/health">Health</a></p>
      </body>
    </html>
  `);
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      table: BIRTHDAYS_TABLE,
      authed: Boolean(req.session.user),
      is_admin: Boolean(req.session.user?.is_admin),
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
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
        ${
          rows.length
            ? `
          <table border="1" cellpadding="8" cellspacing="0">
            <thead><tr><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td>${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank">link</a>` : ""}</td>
                  <td>
                    <form method="POST" action="/me/birthdays/${r.id}/delete" style="display:inline;">
                      <button type="submit" onclick="return confirm('Delete this birthday?')">Delete</button>
                    </form>
                    <details style="display:inline-block; margin-left: 8px;">
                      <summary>Edit</summary>
                      <form method="POST" action="/me/birthdays/${r.id}/edit">
                        <div><label>Name<br/><input name="character_name" value="${escapeHtml(r.character_name)}" required/></label></div>
                        <div><label>MM-DD<br/><input name="mmdd" value="${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}" required/></label></div>
                        <div><label>Image URL<br/><input name="image_url" value="${escapeHtml(r.image_url || "")}" style="width: 460px"/></label></div>
                        <button type="submit">Save</button>
                      </form>
                    </details>
                  </td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        `
            : `<p>No birthdays yet.</p>`
        }
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

    // Only update if this row belongs to the current user
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

// ---------------- Admin: all birthdays + Option B add (raw user id) ----------------
app.get("/admin/birthdays", mustBeAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, user_id, character_name, month, day, image_url
     FROM ${TBL}
     ORDER BY month ASC, day ASC, character_name_key ASC`
  );

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Admin Birthdays</title></head>
      <body style="font-family: system-ui; padding: 24px;">
        <p><a href="/">← Home</a> &nbsp; | &nbsp; <a href="/admin/search">Admin Search</a></p>
        <h2>Admin: All Birthdays</h2>

        <h3>Admin Add (Option B — raw Discord user ID)</h3>
        <form method="POST" action="/admin/birthdays/add">
          <div><label>Discord User ID<br/><input name="user_id" required style="width: 360px"/></label></div>
          <div><label>Character Name<br/><input name="character_name" required style="width: 360px"/></label></div>
          <div><label>Date (MM-DD)<br/><input name="mmdd" placeholder="07-12" required style="width: 120px"/></label></div>
          <div><label>Image URL<br/><input name="image_url" style="width: 560px"/></label></div>
          <button type="submit">Add for user</button>
        </form>

        <hr/>

        <p>Total rows: <b>${rows.length}</b></p>

        ${
          rows.length
            ? `
          <table border="1" cellpadding="8" cellspacing="0">
            <thead><tr><th>User ID</th><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td>${escapeHtml(r.user_id)}</td>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td>${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank">link</a>` : ""}</td>
                  <td>
                    <form method="POST" action="/admin/birthdays/${r.id}/delete" style="display:inline;">
                      <button type="submit" onclick="return confirm('Admin delete this birthday?')">Delete</button>
                    </form>
                  </td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        `
            : `<p>No rows.</p>`
        }
      </body>
    </html>
  `);
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
  const q = String(req.query.q || "").trim();
  let rows = [];

  if (q) {
    if (/^\d{15,25}$/.test(q)) {
      // search by user id
      const r = await pool.query(
        `SELECT id, user_id, character_name, month, day, image_url
         FROM ${TBL}
         WHERE user_id=$1
         ORDER BY month ASC, day ASC, character_name_key ASC`,
        [q]
      );
      rows = r.rows;
    } else {
      // search by character name substring (case-insensitive)
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

  res.setHeader("content-type", "text/html; charset=utf-8");
  res.send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Admin Search</title></head>
      <body style="font-family: system-ui; padding: 24px;">
        <p><a href="/">← Home</a> &nbsp; | &nbsp; <a href="/admin/birthdays">Admin Birthdays</a></p>
        <h2>Admin Search</h2>

        <form method="GET" action="/admin/search">
          <div>
            <label>Search (Discord user id OR character name)</label><br/>
            <input name="q" value="${escapeHtml(q)}" style="width: 420px"/>
            <button type="submit">Search</button>
          </div>
        </form>

        <hr/>

        ${
          q
            ? `<p>Results for <b>${escapeHtml(q)}</b>: ${rows.length}</p>`
            : `<p>Enter a user id (numbers) or a character name.</p>`
        }

        ${
          rows.length
            ? `
          <table border="1" cellpadding="8" cellspacing="0">
            <thead><tr><th>User ID</th><th>Name</th><th>Date</th><th>Image</th><th>Actions</th></tr></thead>
            <tbody>
              ${rows
                .map(
                  (r) => `
                <tr>
                  <td>${escapeHtml(r.user_id)}</td>
                  <td>${escapeHtml(r.character_name)}</td>
                  <td>${String(r.month).padStart(2, "0")}-${String(r.day).padStart(2, "0")}</td>
                  <td>${r.image_url ? `<a href="${escapeHtml(r.image_url)}" target="_blank">link</a>` : ""}</td>
                  <td>
                    <form method="POST" action="/admin/birthdays/${r.id}/delete" style="display:inline;">
                      <button type="submit" onclick="return confirm('Admin delete this birthday?')">Delete</button>
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
            ? `<p>No matches.</p>`
            : ``
        }
      </body>
    </html>
  `);
});

// ---------------- Start ----------------
app.listen(PORT, () => {
  console.log(`[WEB] listening on :${PORT}`);
  console.log(`[WEB] birthdays table: ${BIRTHDAYS_TABLE} (quoted as ${TBL})`);
  console.log(`[WEB] admin role ids: ${ADMIN_ROLE_IDS.length ? ADMIN_ROLE_IDS.join(",") : "(none set)"}`);
});
