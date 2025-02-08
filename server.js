require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const express = require("express");
const app = express();
const db = require("better-sqlite3")("ourApp.db");
db.pragma("journal_mode = WAL");

//Database setup
const createTables = db.transaction(() => {
  db.prepare(
    `
  CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username STRING NOT NULL UNIQUE,
  password STRING NOT NULL
  )
  `
  ).run();
});

//

createTables();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

// middleware

app.use(function (req, res, next) {
  res.locals.errors = [];

  // decoding incoming cookie
  try {
    const decoded = jwt.verfiy(req.cookies.ourSimpleApp, process.env.JWTVAL);
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }
  res.locals.user = req.user;
  console.log(req.user);

  next();
});

//-----------------Pages-------------

app.get("/", (req, res) => {
  res.render("homepage");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/register", (req, res) => {
  const errors = [];

  //checking the type of values entered -- not false for string
  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";
  // trimming any white space
  req.body.username = req.body.username.trim();

  // ----------Username Rules-----------//

  // check for if they didnt write anything
  if (!req.body.username) errors.push("You must provide username");
  // checking for character length
  if (req.body.username && req.body.username.length < 3)
    errors.push("Username cant be shorter than 3 characters");
  if (req.body.username && req.body.username.length > 10)
    errors.push("Username cant be longer than 10 characters");
  //checking for symbols in username
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters and numbers");

  // ----------Password Rules-----------//

  // check for if they didnt write anything
  if (!req.body.password) errors.push("You must provide password");
  // checking for character length
  if (req.body.password && req.body.password.length < 5)
    errors.push("Password cant be shorter than 5 characters");
  if (req.body.password && req.body.password.length > 12)
    errors.push("Password cant be longer than 12 characters");

  if (errors.length) {
    return res.render("homepage", { errors });
  }

  // save the new user into the database
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);

  const ourStatment = db.prepare(
    "INSERT INTO users (username, password) VALUES (?,?)"
  );

  const result = ourStatment.run(req.body.username, req.body.password);

  // SQL DB -- getting id for cookie
  const lookUpState = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const ourUser = lookUpState.get(result.lastInsertRowid);

  // log user in by providing a cookie

  const ourTokenVal = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue",
      userid: ourUser.id,
      username: ourUser.username,
    },
    process.env.JWTVAL
  );
  res.cookie("ourSimpleApp", ourTokenVal, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  res.send("Thank You!");
});

app.listen(3000);
