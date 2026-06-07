require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("./db");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
});


const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
app.use(cookieParser());
app.use(express.json());

app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

function auth(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.send("Not logged in");
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.send("Invalid token");
  }
}

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});



app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});



app.post("/signup", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      [req.body.username, hashedPassword]
    );
    
    res.redirect("/login.html");
    
  } catch (err) {
    console.log(err);
    res.send(err.message);
  }
});

app.post("/login", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [req.body.username]
  );

  if (result.rows.length === 0) {
    return res.send("User Not Found");
  }

  const user = result.rows[0];

  const valid = await bcrypt.compare(
    req.body.password,
    user.password
  );

  if (!valid) {
    return res.send("Wrong Password or Username");
  }

  const token = jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false
  });

  res.redirect("/");
});


app.post("/vote", async (req, res) => {

    const token = req.cookies?.token;
    let user_id = null;

    if (token) {
        try {
            const user = jwt.verify(token, process.env.JWT_SECRET);
            user_id = user.id;
        } catch (err) {
            user_id = null;
        }
    }

    const { option_id, poll_id } = req.body;

    await pool.query(
        `
        INSERT INTO votes (user_id, option_id, poll_id)
        VALUES ($1, $2, $3)
        `,
        [user_id, option_id, poll_id]
    );

    res.redirect("/");
});

app.get("/api/me", (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.json({ loggedIn: false });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);

    res.json({
      loggedIn: true,
      username: user.username
    });
  } catch {
    res.json({ loggedIn: false });
  }
});

app.get("/mypolls", auth, (req, res) => {
    res.sendFile(__dirname + "/mypolls.html");
});


app.get("/api/polls", async (req, res) => {

    try {

        const polls = await pool.query(
          `
          SELECT *
          FROM polls
          WHERE published = TRUE
          ORDER BY id DESC
          `
        );

        const data = [];

        for (const poll of polls.rows) {

            const options = await pool.query(
                `
                SELECT *
                FROM options
                WHERE poll_id = $1
                `,
                [poll.id]
            );

            data.push({
                ...poll,
                options: options.rows
            });
        }

        res.json(data);

    } catch(err) {

        console.log(err);
        res.status(500).send("Server Error");

    }

});



app.post("/createpoll", auth, async (req, res) => {
  const { question, options } = req.body;

  const pollResult = await pool.query(
    `
        INSERT INTO polls(question, creator_id)
        VALUES($1, $2)
        RETURNING id
        `,
    [question, req.user.id]
  );

  const pollId = pollResult.rows[0].id;

  const optionList = options
    .split(",")
    .map(option => option.trim());

  for (const option of optionList) {
    await pool.query(
      "INSERT INTO options (poll_id, option_text) VALUES ($1, $2)",
      [pollId, option]
    );
  }

  res.redirect("/mypolls");
});



app.get("/newpoll", auth, (req, res) => {
  res.sendFile(__dirname + "/newpoll.html");
});

app.get("/api/mypolls", auth, async (req, res) => {

    const polls = await pool.query(
        `
        SELECT *
        FROM polls
        WHERE creator_id = $1
        ORDER BY id DESC
        `,
        [req.user.id]
    );

    const data = [];

    for (const poll of polls.rows) {

        const results = await pool.query(
            `
            SELECT
                o.id,
                o.option_text,
                COUNT(v.id)::int AS votes
            FROM options o
            LEFT JOIN votes v
                ON o.id = v.option_id
            WHERE o.poll_id = $1
            GROUP BY o.id, o.option_text
            `,
            [poll.id]
        );

        data.push({
            ...poll,
            results: results.rows
        });
    }

    res.json(data);
});

app.get("/api/polls/:id/results", async (req, res) => {

    const { id } = req.params;

    const result = await pool.query(
        `
        SELECT o.option_text, COUNT(v.id) as votes
        FROM options o
        LEFT JOIN votes v ON o.id = v.option_id
        WHERE o.poll_id = $1
        GROUP BY o.id
        ORDER BY votes DESC
        `,
        [id]
    );

    res.json(result.rows);
});

app.post("/sharepoll/:id", auth, async (req, res) => {

    await pool.query(
        `
        UPDATE polls
        SET published = TRUE
        WHERE id = $1
        AND creator_id = $2
        `,
        [req.params.id, req.user.id]
    );

    res.send("Poll shared");
});

app.post("/deletepoll/:id", auth, async (req, res) => {

    await pool.query(
        `
        DELETE FROM polls
        WHERE id = $1
        AND creator_id = $2
        `,
        [req.params.id, req.user.id]
    );

    res.send("Poll deleted");
});

app.post("/addoption", auth, async (req, res) => {

    const { poll_id, option_text } = req.body;

    await pool.query(
        `
        INSERT INTO options
        (poll_id, option_text)
        VALUES ($1, $2)
        `,
        [poll_id, option_text]
    );

    res.sendStatus(200);
});



