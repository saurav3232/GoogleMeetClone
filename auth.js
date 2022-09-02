require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const app = express();
const localStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const flash = require("connect-flash");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcrypt");
const findOrCreate= require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
app.set("view engine", "ejs");
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URL);

const userSchema = new mongoose.Schema({
  username: {
    type: String,
  },
  password: {
    type: String,
  },
  googleId:String,
});

userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
  clientID: process.env.client_id,
  clientSecret: process.env.client_secret,
  callbackURL: "http://localhost:3000/auth/google/callback"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));
passport.use(
  new localStrategy(function (username, password, done) {
    User.findOne({ username: username }, function (err, user) {
      if (err) return done(err);
      if (!user) return done(null, false, { message: "Incorrect username." });

      bcrypt.compare(password, user.password, function (err, res) {
        if (err) return done(err);
        if (res === false)
          return done(null, false, { message: "Incorrect password." });
        return done(null, user);
      });
    });
  })
);

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

function isLoggedOut(req, res, next) {
  if (!req.isAuthenticated()) return next();
  res.redirect("/");
}

app.use(flash());
app.use(function (req, res, next) {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  next();
});
app.use(express.static("public"));
let newsData;

app.get("/register", (req, res) => {
  res.render("register");
});
app.get("/login", isLoggedOut, (req, res) => {
  const response = {
    title: "Login",
    error: req.query.error,
  };
  res.render("login", response);
});

app.get("/", isLoggedIn, (req, res) => {
    res.render("index"); 
});

app.get("/auth/google", passport.authenticate('google', {
  scope: ['profile']
}));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });    

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  // Check if all the fields are filled
  let errors = [];
  if (!name || !email || !password) {
    errors.push({ msg: "Please fill in all the fields" });
  }
  // Check password length >= 6
  if (password.length < 6) {
    errors.push({ msg: "Password should be at least 6 characters" });
  }

  if (errors.length > 0) {
    res.render("register", {
      errors,
      name,
      email,
      password,
    });
  } else {
    const exists = await User.exists({ username: req.body.email });
    if (exists) {
      errors.push({ msg: "Email already registered" });
      res.render("register", {
        errors,
        name,
        email,
        password,
      });
    }
    else{
      bcrypt.genSalt(10, function (err, salt) {
        if (err) return next(err);
        bcrypt.hash(req.body.password, salt, function (err, hash) {
          if (err) return next(err);
    
          const newAdmin = new User({
            username: req.body.email,
            password: hash,
          });
    
          newAdmin.save();
    
          res.redirect("/login");
        });
      });
    }
  }
});
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login?error=true",
  })
);
app.get("/logout", function (req, res) {
  req.logOut(() => {
    res.redirect("/login");
  });
});
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});