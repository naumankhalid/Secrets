//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// const encrypt = require('mongoose-encryption');  // this uses SHA-256 encryption algorithm to encrypt passwords
// const _ = require("lodash");

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({
  secret: 'Our little secret',
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
mongoose.set("useUnifiedTopology", true);
mongoose.set("useCreateIndex", true);
// Creating the user schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: {type: Array, "default": []}
});

userSchema.plugin(passportLocalMongoose); //plugin used to hash and salt passwords and save it into the MongoDB database.
userSchema.plugin(findOrCreate); //plugin for the findOrCreate package
// console.log(process.env.API_KEY);
// adding the encrypt plugin to the userSchema so that the passwords are encrypted before saving into the database.
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// This works only if we serialize and deserialize using passport-local-mongoose
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //This is used to retrieve user profile info from this link instead of Google+
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    console.log(profile._json.email);
    User.findOrCreate({ googleId: profile.id, email: profile._json.email }, function (err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({facebookId: profile.id}, function(err, user) {
      if (err) { return done(err); }
      done(null, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});


// Route for Google OAuth
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Route redirected to by Google after authentication is successful
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

// Route for Facebook OAuth
app.get("/auth/facebook",
    passport.authenticate("facebook")
);

// Route redirected to by Facebook after successful authentication
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {

    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

// Login route - renders the login page
app.get("/login", function(req, res){
  res.render("login");
});


app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }

});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    console.log(req.user);
    User.findById(req.user.id, function(err, foundUser){
      if(err){
        console.log(err);
      }else{
        if (foundUser){
          foundUser.secret.push(submittedSecret);
          foundUser.save(function(){
            res.redirect("/secrets");
          });
        }else{
          console.log("User not found");
        }
      }
    });

});

// Register route - renders the register page
app.get("/register", function(req, res){
  res.render("register");
});

// Secrets route - check if the user is authenticated and then renders the secrets page
app.get("/secrets", function(req, res){
  if(req.isAuthenticated()){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
      if(err){
        console.log(err);
      }else {
        if (foundUsers){
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });

  }else{
    res.redirect("/login");
  }

});

// Logout route - logs the user out of the application
app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
})

// Regiter post route - a new user registration request is routed here
app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

//Register route with bcrypt

// app.post("/register", function(req, res){
//   bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//     const newUser = new User({
//       email: req.body.username,
//       password: hash
//     });
//     newUser.save(function(err){
//       if(err){
//         console.log(err);
//       }else{
//         res.render("secrets");
//       }
//     });
// });
//
// });


// Login post route - login request is routed here
app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
      res.redirect("/login");
    } else{
      passport.authenticate("local", {failureRedirect: "/login", failureFlash: "Invalid username or password!"})(req, res, function(){
        res.redirect("/secrets");
      });
    }
  })

});


//Login route with bcrypt

// app.post("/login", function(req, res){
//
//   const username = req.body.username;
//   const password = req.body.password;
//   User.findOne({email: username}, function(err, foundUser){
//     if(err){            //if some error occurs, log the error
//       console.log(err);
//     }else{
//       if(foundUser){         //if user found, compare the hash password in the db against the one entered byt the user
//         bcrypt.compare(password, foundUser.password, function(err, result) {
//             if (result === true){                        //if it matches, render the secrets page.
//                 res.render("secrets");
//             }else{                                       //else redirect to the login page
//               res.render("login");
//             }
//         });
//       }else{                                            // if user not found, redirect to the login page
//         res.render("login");
//       }
//     }
//
//   });
//
//
// });

app.listen(3000, function(req, res) {
  console.log("Server started on port 3000");
});
