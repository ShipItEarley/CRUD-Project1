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

app.use(function (req, res, next) {
  res.locals.errors = [];
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
  db.prepare("INSERT INTO users (username, password) VALUE (?,?)");
  // log user in by providign a cookie
});

app.listen(3000);
