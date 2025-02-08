const express = require("express");
const app = express();

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

  if (errors.length) {
    return res.render("homepage", { errors });
  } else {
    res.send("Thank You For Signing up");
  }
});

app.listen(3000);
