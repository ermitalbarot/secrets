require('dotenv').config()
const bodyParser = require("body-parser")
const express = require("express")
const ejs = require("ejs")
const mongoose = require('mongoose')
const session = require('express-session')
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const LocalStrategy = require("passport-local").Strategy; // <--- ADD THIS LINE
const GoogleStrategy = require('passport-google-oauth20').Strategy
const findOrCreate = require('mongoose-findorcreate')
const app = express()
app.use(express.static("public"))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({
    extended: true
}))
app.use(session({
    secret: "our little secret.",
    resave: false,
    saveUninitialized: false

}))
app.use(passport.initialize())
app.use(passport.session())
mongoose.connect('mongodb://127.0.0.1:27017/userDB')
const db = mongoose.connection
db.once('open', () => {
    console.log("mongodb connection")
})

// Add an error listener for the database connection
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)
const User = new mongoose.model("User", userSchema)

// Corrected line for setting up the local strategy
passport.use(new LocalStrategy(User.authenticate())); // <--- CORRECTED LINE

passport.serializeUser(function(user, done){
    done(null, user.id)
})
passport.deserializeUser(async function(id, done) { // Make the function async
    try {
        const user = await User.findById(id); // Await the promise
        done(null, user); // Pass null for error if successful
    } catch (err) {
        done(err); // Pass the error if something goes wrong
    }
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home")
})
app.get("/auth/google",
    passport.authenticate('google',{scope: ["profile"] })
)
app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get("/login", function(req, res) {
    res.render("login")
})
app.get("/register", function(req, res) {
    res.render("register")
})
app.get("/secrets", async function(req, res) {
    try {
        const foundUsers = await User.find({"secret": {$ne: null}});
        res.render("secrets", {userswithsecrets: foundUsers}); // Changed to userswithsecrets
    } catch (err) {
        console.log(err);
        res.status(500).send("An error occurred while fetching secrets.");
    }
});
app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit")
    } else{
        res.redirect("/login")
    }
})
app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    console.log(req.user.id);

    User.findById(req.user.id) // No callback here!
        .then(foundUser => {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                return foundUser.save(); // Return the promise from save()
            } else {
                // Handle case where user is not found (though less likely with authenticated user ID)
                console.log("User not found despite being authenticated.");
                res.status(404).send("User not found.");
            }
        })
        .then(() => { // This .then() executes after foundUser.save() completes
            res.redirect("/secrets");
        })
        .catch(err => { // This .catch() handles errors from findById or save
            console.log(err);
            res.status(500).send("An error occurred."); // Send an appropriate error response
        });
});
app.get("/logout", function(req, res) {
  req.logout(function(err) { // Corrected: Passport's req.logout() should be asynchronous
    if (err) {
      return next(err); // Handle errors, perhaps by logging them and redirecting to an error page
    }
    res.redirect("/"); // Redirect to the homepage or another appropriate page
  });
});

app.post("/register", function(req, res) {
    User.register({
        username: req.body.username
    }, req.body.password, function(err, user) {
        if (err) {
            console.log(err)
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets")
            })
        }
    })
});

app.post("/login", function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});
app.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.listen(3000, function() {
    console.log("Server started on port 3000.");
})