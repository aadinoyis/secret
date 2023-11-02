//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session')
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.get("/about", function(req, res) {
    res.render("about"); // Renders the "about.ejs" page
});




app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// mongoose.connect("mongodb://0.0.0.0:27017/userDB", {useNewUrlParser: true});
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true });

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String,
  username: String, // Make username field optional
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id)
      .then(user => {
        done(null, user);
      })
      .catch(err => {
        done(err, null);
      });
  });

  passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:5000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  async (accessToken, refreshToken, profile, cb) => {
    try {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        // Create a new user with an optional username field
        user = new User({ googleId: profile.id });
      }

      user.username = profile.displayName; // Use Google profile's displayName as username
      await user.save();
      return cb(null, user);
    } catch (err) {
      return cb(err);
    }
  }
));


app.get("/", function(req, res){
    res.render("home")
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
    res.render("login")
});

app.get("/register", function(req, res){
    res.render("register")
});

app.get("/secrets", function(req, res) {
    if (req.isAuthenticated()) {
        User.find({"secret": {$ne: null}})
            .then(foundUsers => {
                res.render("secrets", { usersWithSecrets: foundUsers });
            })
            .catch(err => {
                console.log(err);
                res.status(500).send('Internal Server Error');
            });
    } else {
        res.redirect("/login");
    }
});


app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    };
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
  
    // Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);
  
    User.findById(req.user.id)
        .then(foundUser => {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                return foundUser.save();
            } else {
                return Promise.reject(new Error("User not found"));
            }
        })
        .then(() => {
            res.redirect("/secrets");
        })
        .catch(error => {
            console.log(error);
            res.status(500).send('Internal Server Error');
        });
});


app.get("/logout", function(req, res){
    req.logout(function(err) {
        if (err) {
            console.log(err);
        }
        res.redirect("/");
    });
});


app.post('/register', function(req, res) {

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
    console.log(err);
    res.redirect("/")
    } else{
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
    })
    }
  })
    
});
 
app.post('/login', function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
      });
      req.login(user, function(err){
        if (err) {
          console.log(err);
        } else {
          passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
          });
        }
      });
});







app.listen(process.env.PORT || 5000, function() {
    console.log("Server started on port 5000.");
});