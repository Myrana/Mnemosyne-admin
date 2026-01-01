import express from "express";
import session from "express-session";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is missing");
if (!process.env.SESSION_SECRET) throw new Error("SESSION_SECRET is missing");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

// ---------- helpers ----------
function esc(s = "") {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function rowToMMDD(row) {
  const m = String(row.month).padStart(2, "0");
  const d = String(row.day).padStart(2, "0");
  return `${m}-${d}`;
}

// ---------- ROUTES ----------

// Home = Add form + link to list
app.get("/", (req, res) => {
  res.send(`
    <h2>Mnemosyne — Birthdays Admin</h2>
    <p><a href="/birthdays">View / Edit / Delete birthdays</a></p>
    <hr/>

    <h3>Add / Upsert Birthday</h3>
    <form method="POST" action="/add">
      <label>User ID</label><br/>
      <input name="user_id" required /><br/><br/>

      <label>Character Name</label><br/>
      <input name="character_name" required /><br/><br/>

      <label>Month (1-12)</label><br/>
      <input type="number" name="month" min="1" max="12" required /><br/><br/>

      <label>Day (1-31)</label><br/>
      <input type="number" name="day" min="1" max="31" required /><br/><br/>

      <label>Image URL</label><br/>
      <input name="image_url" /><br/><br/>

      <button type="submit">Save</button>
    </form>
  `);
});

// Create / Upsert
app.post("/add", async (req, res) => {
  const user_id = String(req.body.user_id || "").trim();
  const character_name = String(req.body.character_name || "").trim();
  const month = Number(req.body.month);
  const day = Number(req.body.day);
  const image_url = String(req.body.image_url || "").trim() || null;

  if (!user_id || !character_name || !month || !day) {
    return res.status(400).send("Missing required fields.");
  }

  try {
    await pool.query(
      `
      INSERT INTO birthdays (user_id, character_name, month, day, image_url)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (user_id, lower(character_name))
      DO UPDATE SET
        month = EXCLUDED.month,
        day = EXCLUDED.day,
        image_url = EXCLUDED.image_url;
      `,
      [user_id, character_name, month, day, image_url]
    );

    res.redirect("/birthdays");
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error saving birthday.");
  }
});

// List birthdays (+ optional search)
app.get("/birthdays", async (req, res) => {
  const q = String(req.query.q || "").trim();

  try {
    const { rows } = await pool.query(
      q
        ? `
          SELECT id, user_id, character_name, month, day, image_url
          FROM birthdays
          WHERE
            user_id ILIKE $1
            OR character_name ILIKE $1
          ORDER BY month, day, lower(character_name)
        `
        : `
          SELECT id, user_id, character_name, month, day, image_url
          FROM birthdays
          ORDER BY month, day, lower(character_name)
        `,
      q ? [`%${q}%`] : []
    );

    const listHtml = rows
      .map(
        (r) => `
        <tr>
          <td>${esc(r.user_id)}</td>
          <td>${esc(r.character_name)}</td>
          <td>${esc(rowToMMDD(r))}</td>
          <td>${r.image_url ? `<a href="${esc(r.image_url)}" target="_blank">image</a>` : ""}</td>
          <td>
            <a href="/birthdays/${r.id}/edit">edit</a>
            &nbsp;|&nbsp;
            <form method="POST" action="/birthdays/${r.id}/delete" style="display:inline"
              onsubmit="return confirm('Delete ${esc(r.character_name)}?');">
              <button type="submit">delete</button>
            </form>
          </td>
        </tr>
      `
      )
      .join("");

    res.send(`
      <h2>Birthdays</h2>
      <p><a href="/">+ Add new</a></p>

      <form method="GET" action="/birthdays" style="margin-bottom: 12px;">
        <input name="q" placeholder="search user_id or character" value="${esc(q)}" />
        <button type="submit">Search</button>
        ${q ? `<a href="/birthdays" style="margin-left:10px;">Clear</a>` : ""}
      </form>

      <table border="1" cellpadding="6" cellspacing="0">
        <thead>
          <tr>
            <th>User ID</th>
            <th>Character</th>
            <th>Date</th>
            <th>Image</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${listHtml || `<tr><td colspan="5">No results</td></tr>`}
        </tbody>
      </table>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error loading birthdays.");
  }
});

// Edit form
app.get("/birthdays/:id/edit", async (req, res) => {
  const id = Number(req.params.id);

  try {
    const { rows } = await pool.query(
      `SELECT id, user_id, character_name, month, day, image_url
       FROM birthdays
       WHERE id=$1`,
      [id]
    );

    const r = rows[0];
    if (!r) return res.status(404).send("Not found.");

    res.send(`
      <h2>Edit Birthday</h2>
      <p><a href="/birthdays">← Back to list</a></p>

      <form method="POST" action="/birthdays/${r.id}/edit">
        <label>User ID</label><br/>
        <input name="user_id" value="${esc(r.user_id)}" required /><br/><br/>

        <label>Character Name</label><br/>
        <input name="character_name" value="${esc(r.character_name)}" required /><br/><br/>

        <label>Month (1-12)</label><br/>
        <input type="number" name="month" min="1" max="12" value="${esc(r.month)}" required /><br/><br/>

        <label>Day (1-31)</label><br/>
        <input type="number" name="day" min="1" max="31" value="${esc(r.day)}" required /><br/><br/>

        <label>Image URL</label><br/>
        <input name="image_url" value="${esc(r.image_url || "")}" /><br/><br/>

        <button type="submit">Save Changes</button>
      </form>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error loading record.");
  }
});

// Edit submit
app.post("/birthdays/:id/edit", async (req, res) => {
  const id = Number(req.params.id);
  const user_id = String(req.body.user_id || "").trim();
  const character_name = String(req.body.character_name || "").trim();
  const month = Number(req.body.month);
  const day = Number(req.body.day);
  const image_url = String(req.body.image_url || "").trim() || null;

  if (!user_id || !character_name || !month || !day) {
    return res.status(400).send("Missing required fields.");
  }

  try {
    // update by id
    await pool.query(
      `
      UPDATE birthdays
      SET user_id=$1, character_name=$2, month=$3, day=$4, image_url=$5
      WHERE id=$6
      `,
      [user_id, character_name, month, day, image_url, id]
    );

    res.redirect("/birthdays");
  } catch (err) {
    // If you edited it into a duplicate (same user_id + same name ignoring case),
    // Postgres unique index will throw — show a friendly message.
    console.error(err);
    res.status(500).send("Database error saving changes (maybe duplicate name for same user?).");
  }
});

// Delete
app.post("/birthdays/:id/delete", async (req, res) => {
  const id = Number(req.params.id);

  try {
    await pool.query(`DELETE FROM birthdays WHERE id=$1`, [id]);
    res.redirect("/birthdays");
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error deleting record.");
  }
});

app.listen(PORT, () => {
  console.log(`Admin app running on port ${PORT}`);
});
