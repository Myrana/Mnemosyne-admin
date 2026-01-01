import "dotenv/config";
import express from "express";
import session from "express-session";
import pg from "pg";
import pgSession from "connect-pg-simple";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";

const {
  DATABASE_URL,
  SESSION_SECRET,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_GUILD_ID,
  ADMIN_ROLE_IDS,
  DISCORD_BOT_TOKEN,
} = process.env;

const PORT = process.env.PORT || 3000;

// ---- basic env checks (helpful instead of mystery errors)
function requireEnv(name) {
  if (!process.env[name]) throw new Error(`Missing required env var: ${name}`);
}
[
  "DATABASE_URL",
  "SESSION_SECRET",
  "DISCORD_CLIENT_ID",
  "DISCORD_CLIENT_SECRET",
  "DISCORD_REDIRECT_URI",
  "DISCORD_GUILD_ID",
  "ADMIN_ROLE_IDS",
  "DISCORD_BOT_TOKEN",
].forEach(requireEnv);

const adminRoleIds = (ADMIN_ROLE_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ---- Postgres pool
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
});

// ---- sessions stored in Postgres (recommended on Railway)
const PgStore = pgSession(session);
const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    store: new PgStore({ pool, tableName: "web_sessions" }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: true, // Railway is HTTPS
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---------- helpers ----------
function cleanName(s = "") {
  return String(s).replace(/\s+/g, " ").trim();
}
function nameKey(s = "") {
  return cleanName(s).toLowerCase();
}
function clampInt(n, min, max) {
  const x = Number.parseInt(n, 10);
  if (Number.isNaN(x)) return null;
  return Math.min(max, Math.max(min, x));
}
function requireLogin(req, res, next) {
  if (!req.session?.user) return res.redirect("/login");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session?.user?.is_admin) return res.status(403).send("Admins only.");
  next();
}

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
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!r.ok) {
    const text = await r.text();
    throw new Error(`Token exchange failed: ${r.status} ${text}`);
  }
  return r.json();
}

async function discordGetUser(accessToken) {
  const r = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) throw new Error(`Fetch user failed: ${r.status}`);
  return r.json();
}

// Fetch member roles using BOT token (server-side, reliable)
async function discordGetMemberRoles(userId) {
  const url = `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`;
  const r = await fetch(url, {
    headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
  });

  // If the user isn't in the server, this will 404.
  if (r.status === 404) return [];
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`Fetch member failed: ${r.status} ${text}`);
  }

  const member = await r.json();
  return member.roles || [];
}

function isAdminByRoles(roles = []) {
  return roles.some((rid) => adminRoleIds.includes(rid));
}

// ---------- DB: ensure table exists ----------
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS birthdays (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      character_name TEXT NOT NULL,
      character_name_key TEXT NOT NULL,
      month INT NOT NULL CHECK (month BETWEEN 1 AND 12),
      day INT NOT NULL CHECK (day BETWEEN 1 AND 31),
      image_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE (user_id, character_name_key)
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS birthdays_user_id_idx ON birthdays(user_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS birthdays_month_day_idx ON birthdays(month, day);`);
}

// run once on boot
ensureSchema().catch((e) => {
  console.error("[BOOT] schema ensure failed:", e);
  process.exit(1);
});

// ---------- Routes ----------
app.get("/", (req, res) => {
  res.render("home", { user: req.session.user || null });
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
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify",
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

// Discord OAuth callback
app.get("/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send("Missing ?code");

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

    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[OAUTH] error:", e);
    res.status(500).send(`OAuth error: ${e.message}`);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ---- MEMBER: list mine
app.get("/me/birthdays", requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const { rows } = await pool.query(
    `SELECT id, character_name, month, day, image_url
     FROM birthdays
     WHERE user_id=$1
     ORDER BY month, day, lower(character_name)`,
    [userId]
  );
  res.render("me", { user: req.session.user, rows, error: null });
});

// ---- MEMBER: add mine
app.post("/me/birthdays", requireLogin, async (req, res) => {
  const userId = req.session.user.id;

  const character_name = cleanName(req.body.character_name);
  const month = clampInt(req.body.month, 1, 12);
  const day = clampInt(req.body.day, 1, 31);
  const image_url = cleanName(req.body.image_url || "") || null;
  const character_name_key = nameKey(character_name);

  try {
    if (!character_name) throw new Error("Character name is required.");
    if (!month || !day) throw new Error("Month/day invalid.");

    await pool.query(
      `INSERT INTO birthdays (user_id, character_name, character_name_key, month, day, image_url, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6, now())
       ON CONFLICT (user_id, character_name_key)
       DO UPDATE SET
         character_name=EXCLUDED.character_name,
         month=EXCLUDED.month,
         day=EXCLUDED.day,
         image_url=EXCLUDED.image_url,
         updated_at=now()`,
      [userId, character_name, character_name_key, month, day, image_url]
    );

    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[DB] save birthday error:", e);

    const { rows } = await pool.query(
      `SELECT id, character_name, month, day, image_url
       FROM birthdays
       WHERE user_id=$1
       ORDER BY month, day, lower(character_name)`,
      [userId]
    );

    res.render("me", { user: req.session.user, rows, error: e.message });
  }
});

// ---- MEMBER: edit mine
app.post("/me/birthdays/:id/edit", requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const id = req.params.id;

  const character_name = cleanName(req.body.character_name);
  const month = clampInt(req.body.month, 1, 12);
  const day = clampInt(req.body.day, 1, 31);
  const image_url = cleanName(req.body.image_url || "") || null;
  const character_name_key = nameKey(character_name);

  try {
    if (!character_name) throw new Error("Character name is required.");
    if (!month || !day) throw new Error("Month/day invalid.");

    const result = await pool.query(
      `UPDATE birthdays
       SET character_name=$1,
           character_name_key=$2,
           month=$3,
           day=$4,
           image_url=$5,
           updated_at=now()
       WHERE id=$6 AND user_id=$7`,
      [character_name, character_name_key, month, day, image_url, id, userId]
    );

    if (result.rowCount === 0) throw new Error("Not found (or not yours).");

    res.redirect("/me/birthdays");
  } catch (e) {
    console.error("[DB] edit error:", e);
    res.redirect("/me/birthdays");
  }
});

// ---- MEMBER: delete mine
app.post("/me/birthdays/:id/delete", requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const id = req.params.id;
  try {
    await pool.query(`DELETE FROM birthdays WHERE id=$1 AND user_id=$2`, [id, userId]);
  } catch (e) {
    console.error("[DB] delete error:", e);
  }
  res.redirect("/me/birthdays");
});

// ---- ADMIN: list all
app.get("/admin/birthdays", requireLogin, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, user_id, character_name, month, day, image_url
     FROM birthdays
     ORDER BY month, day, lower(character_name)`
  );
  res.render("admin", { user: req.session.user, rows });
});

// ---- ADMIN: edit any
app.post("/admin/birthdays/:id/edit", requireLogin, requireAdmin, async (req, res) => {
  const id = req.params.id;

  const character_name = cleanName(req.body.character_name);
  const month = clampInt(req.body.month, 1, 12);
  const day = clampInt(req.body.day, 1, 31);
  const image_url = cleanName(req.body.image_url || "") || null;
  const character_name_key = nameKey(character_name);

  try {
    await pool.query(
      `UPDATE birthdays
       SET character_name=$1,
           character_name_key=$2,
           month=$3,
           day=$4,
           image_url=$5,
           updated_at=now()
       WHERE id=$6`,
      [character_name, character_name_key, month, day, image_url, id]
    );
  } catch (e) {
    console.error("[DB][ADMIN] edit error:", e);
  }
  res.redirect("/admin/birthdays");
});

// ---- ADMIN: delete any
app.post("/admin/birthdays/:id/delete", requireLogin, requireAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query(`DELETE FROM birthdays WHERE id=$1`, [id]);
  } catch (e) {
    console.error("[DB][ADMIN] delete error:", e);
  }
  res.redirect("/admin/birthdays");
});

app.listen(PORT, () => console.log(`[WEB] listening on :${PORT}`));
