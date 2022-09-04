"use strict";
require("dotenv").config();
var http = require("http");
var https = require("https");
var fs = require("fs");
var WebSocketServer = require("websocket").server;
const ejs = require("ejs");
const localStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const flash = require("connect-flash");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcrypt");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
let express = require("express");
var reqId="";
let app = express();
app.set("view engine", "ejs");
app.use(express.static("public"));
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
  googleId: String,
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
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.client_id,
      clientSecret: process.env.client_secret,
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

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
      failureRedirect: "/login?error=true"
    })
  );
  app.get("/logout", function (req, res) {
    req.logOut(() => {
      res.redirect("/login");
    });
  });


app.get("/", isLoggedIn, (req, res) => {
  res.render("index", { target: "skip" });
});

app.get("/:id", isLoggedIn,(req, res) => {
    reqId=req.params.id;    
    res.render('index',{target:reqId})
});
const keyFilePath = "/etc/pki/tls/private/mdn-samples.mozilla.org.key";
const certFilePath = "/etc/pki/tls/certs/mdn-samples.mozilla.org.crt";

var connectionArray = [];
var nextID = Date.now();
var appendToMakeUnique = 1;

function log(text) {
  var time = new Date();

  console.log("[" + time.toLocaleTimeString() + "] " + text);
}

var httpsOptions = {
  key: null,
  cert: null,
};

try {
  httpsOptions.key = fs.readFileSync(keyFilePath);
  try {
    httpsOptions.cert = fs.readFileSync(certFilePath);
  } catch (err) {
    httpsOptions.key = null;
    httpsOptions.cert = null;
  }
} catch (err) {
  httpsOptions.key = null;
  httpsOptions.cert = null;
}

var webServer = null;

try {
  if (httpsOptions.key && httpsOptions.cert) {
    webServer = https.createServer(httpsOptions, app);
  }
} catch (err) {
  webServer = null;
}

if (!webServer) {
  try {
    webServer = http.createServer({}, app);
  } catch (err) {
    webServer = null;
    log(`Error attempting to create HTTP(s) server: ${err.toString()}`);
  }
}

/*
function handleWebRequest(request, response) {
    log("Received request for " + request.url+' '+request.origin);
    response.writeHead(404);
    response.end();
}
*/
webServer.listen(3000, function () {
  log("Server is listening on port 3000");
});
var wsServer = new WebSocketServer({
  httpServer: webServer,
  autoAcceptConnections: false,
});
if (!wsServer) {
  log("ERROR: Unable to create WbeSocket server!");
}

function originIsAllowed(origin) {
  console.log("origin " + origin);
  return true; // We will accept all connections
}

function isUsernameUnique(name) {
  var isUnique = true;
  var i;

  for (i = 0; i < connectionArray.length; i++) {
    if (connectionArray[i].username === name) {
      isUnique = false;
      break;
    }
  }
  return isUnique;
}

function sendToOneUser(target, msgString) {
  var isUnique = true;
  var i;

  for (i = 0; i < connectionArray.length; i++) {
    if (connectionArray[i].username === target) {
      connectionArray[i].sendUTF(msgString);
      break;
    }
  }
}
function getConnectionForID(id) {
  var connect = null;
  var i;

  for (i = 0; i < connectionArray.length; i++) {
    if (connectionArray[i].clientID === id) {
      connect = connectionArray[i];
      break;
    }
  }

  return connect;
}
wsServer.on("request", function (request) {
  if (!originIsAllowed(request.origin)) {
    request.reject();
    log("Connection from " + request.origin + " rejected.");
    return;
  }
  //always accepted
  var connection = request.accept("json", request.origin);
  log("Connection accepted from " + connection.remoteAddress + ".");
  connectionArray.push(connection);

  connection.clientID = nextID;
  nextID++;
  var msg = {
    type: "id",
    id: connection.clientID,
  };
  connection.sendUTF(JSON.stringify(msg));
  connection.on("message", function (message) {
    if (message.type === "utf8") {
      log("Received Message: " + message.utf8Data);
      var sendToClients = true;
      msg = JSON.parse(message.utf8Data);
      var connect = getConnectionForID(msg.id);
      switch (msg.type) {
        // Public, textual message
        case "message":
          msg.name = connect.username;
          msg.text = msg.text.replace(/(<([^>]+)>)/gi, "");
          break;

        // Username change
        case "username":
          var nameChanged = false;
          var origName = msg.name;

          // Ensure the name is unique by appending a number to it
          // if it's not; keep trying that until it works.
          while (!isUsernameUnique(msg.name)) {
            msg.name = origName + appendToMakeUnique;
            appendToMakeUnique++;
            nameChanged = true;
          }

          // If the name had to be changed, we send a "rejectusername"
          // message back to the user so they know their name has been
          // altered by the server.
          if (nameChanged) {
            var changeMsg = {
              id: msg.id,
              type: "rejectusername",
              name: msg.name,
            };
            connect.sendUTF(JSON.stringify(changeMsg));
          }

          // Set this connection's final username and send out the
          // updated user list to all users. Yeah, we're sending a full
          // list instead of just updating. It's horribly inefficient
          // but this is a demo. Don't do this in a real app.
          connect.username = msg.name;
          sendToClients = false; // We already sent the proper responses
          break;
      }
      if (sendToClients) {
        var msgString = JSON.stringify(msg);
        var i;

        // If the message specifies a target username, only send the
        // message to them. Otherwise, send it to every user.
        if (msg.target && msg.target !== undefined && msg.target.length !== 0) {
          sendToOneUser(msg.target, msgString);
        }
      }
    }
  });
  connection.on("close", function (reason, description) {
    // First, remove the connection from the list of connections.
    connectionArray = connectionArray.filter(function (el, idx, ar) {
      return el.connected;
    });

    var logMessage =
      "Connection closed: " + connection.remoteAddress + " (" + reason;
    if (description !== null && description.length !== 0) {
      logMessage += ": " + description;
    }
    logMessage += ")";
    log(logMessage);
  });
});
