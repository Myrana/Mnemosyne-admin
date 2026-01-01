import express from "express";
import session from "express-session";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing");
}
if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing");
}

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

/* ---------- ROUTES ---------- */

app.get("/", (req, res) => {
  res.send(`
    <h2>Add Birthday</h2>
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

app.post("/add", async (req, res) => {
  const { user_id, character_name, month, day, image_url } = req.body;

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
      [user_id, character_name.trim(), month, day, image_url || null]
    );

    res.send("<p>Saved ✔</p><a href='/'>Add another</a>");
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error");
  }
});

app.listen(PORT, () => {
  console.log(`Admin app running on port ${PORT}`);
});
