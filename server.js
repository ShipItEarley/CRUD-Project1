require("dotenv").config(); // Load environment variables from .env file
const sanitizeHTML = require("sanitize-html");
const jwt = require("jsonwebtoken"); // Import JWT for authentication
const bcrypt = require("bcrypt"); // Import bcrypt for password hashing
const cookieParser = require("cookie-parser"); // Import cookie parser to handle cookies
const express = require("express"); // Import Express framework
const sanitizeHtml = require("sanitize-html");
const db = require("better-sqlite3")("ourApp.db"); // Initialize SQLite database

db.pragma("journal_mode = WAL"); // Enable Write-Ahead Logging for better performance

// Create users table if it does not exist
const createTables = db.transaction(() => {
  db.prepare(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username STRING NOT NULL UNIQUE,
      password STRING NOT NULL
    )`
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorID INTEGER,
    FOREIGN KEY (authorID) REFERENCES users (id))`
  ).run();
});

createTables(); // Execute table creation

const app = express(); // Initialize Express application
app.set("view engine", "ejs"); // Set EJS as the templating engine
app.use(express.urlencoded({ extended: false })); // Enable form data parsing
app.use(express.static("public")); // Serve static files from 'public' folder
app.use(cookieParser()); // Enable cookie parsing

// Middleware to check authentication and set user data
app.use(function (req, res, next) {
  res.locals.errors = []; // Initialize an empty error list

  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTVAL); // Verify JWT token
    req.user = decoded; // Set user data if valid
  } catch (err) {
    req.user = false; // Set user as false if token verification fails
  }
  res.locals.user = req.user; // Store user data in locals for templates
  next(); // Proceed to the next middleware
});

// ------------Page Routes--------

app.get("/", (req, res) => {
  if (req.user) return res.render("dashboard"); // If logged in, show dashboard
  res.render("homepage"); // Otherwise, show homepage
});

// Login
app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp");
  res.redirect("/");
});

app.post("/login", (req, res) => {
  let errors = [];

  // Clean inputs
  req.body.username =
    typeof req.body.username === "string" ? req.body.username.trim() : "";

  req.body.password =
    typeof req.body.password === "string" ? req.body.password : "";

  // Combined validation check
  if (req.body.username === "" || req.body.password === "") {
    errors.push("Invalid username / Password");
  }

  if (errors.length) {
    return res.render("login", {
      errors,
      username: req.body.username,
      password: req.body.password,
    });
  }

  const userInQuestion = db.prepare("SELECT * FROM users WHERE USERNAME = ?");
  const userInQue = userInQuestion.get(req.body.username);

  if (!userInQue) {
    errors = ["Invalid username / Password"];
    return res.render("login", { errors });
  }

  const matchOrNot = bcrypt.compareSync(req.body.password, userInQue.password);

  if (!matchOrNot) {
    errors = ["Invalid username / Password"];
    return res.render("login", { errors });
  }

  const ourTokenVal = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue",
      userid: userInQue.id,
      username: userInQue.username,
    },
    process.env.JWTVAL
  );

  res.cookie("ourSimpleApp", ourTokenVal, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  res.redirect("/dashboard");
});

// Dashboard
// Redirect to homepage if not logged in ---- Render dashboard  if logged in
app.get("/dashboard", (req, res) => {
  if (!req.user) {
    return res.redirect("/");
  }
  res.render("dashboard");
});

// Middleware -- Verify login for create post

function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}

app.get("/create-post", mustBeLoggedIn, (req, res) => {
  res.render("create-post");
});

function sharedPostVal(req) {
  const errors = [];

  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";

  // Trim, Sanitize or Strip out HTML

  req.body.title = sanitizeHtml(req.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });
  req.body.body = sanitizeHtml(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!req.body.title) errors.push("You must provide a title.");
  if (!req.body.body) errors.push("You must provide content.");

  return errors;
}

app.post("/create-post", mustBeLoggedIn, (req, res) => {
  const errors = sharedPostVal(req);

  if (errors.length) {
    return res.render("create-post", { errors });
  }

  // Save Posts To DB
  const ourStatment = db.prepare(
    "INSERT INTO posts (title, body, authorID, createdDate ) VALUES(?,?,?,?)"
  );

  const result = ourStatment.run(
    req.body.title,
    req.body.body,
    req.user.userid,
    new Date().toISOString()
  );

  const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?");
  const realPost = getPostStatement.get(result.lastInsertRowid);
  res.redirect(`/post/${realPost.id}`);
});

// User registration
app.post("/register", (req, res) => {
  const errors = [];

  // Ensure username and password are strings
  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();

  // Validate username
  if (!req.body.username) errors.push("You must provide a username");

  if (req.body.username.length < 3)
    errors.push("Username must be at least 3 characters long");

  if (req.body.username.length > 10)
    errors.push("Username cannot exceed 10 characters");

  if (!req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters and numbers");

  // Validate password
  if (!req.body.password) errors.push("You must provide a password");

  if (req.body.password.length < 5)
    errors.push("Password must be at least 5 characters long");

  if (req.body.password.length > 12)
    errors.push("Password cannot exceed 12 characters");

  // If there are errors, re-render homepage with error messages
  if (errors.length) {
    return res.render("homepage", { errors });
  }

  // Check if username is already taken
  const checkUser = db.prepare("SELECT * FROM users WHERE username = ?");
  const existingUser = checkUser.get(req.body.username);

  if (existingUser) {
    errors.push("Username Already Taken");
    return res.render("homepage", { errors });
  }

  // Hash the password for security
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);

  // Insert new user into the database
  const ourStatment = db.prepare(
    "INSERT INTO users (username, password) VALUES (?,?)"
  );

  const result = ourStatment.run(req.body.username, req.body.password);

  // Retrieve newly inserted user
  const lookUpState = db.prepare("SELECT * FROM users WHERE ROWID = ?");

  const ourUser = lookUpState.get(result.lastInsertRowid);

  // Generate JWT token for authentication
  const ourTokenVal = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue", // Example payload data
      userid: ourUser.id, // Store user ID in token
      username: ourUser.username, // Store username in token
    },
    process.env.JWTVAL
  );

  // Store JWT token in HTTP-only, secure cookie
  res.cookie("ourSimpleApp", ourTokenVal, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24, // Cookie valid for 24 hours
  });

  res.redirect("/dashboard");
});

app.listen(3000); // Start server on port 3000
