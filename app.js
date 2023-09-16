//jshint esversion:6
require('dotenv').config();
const express = require('express')
const bodyParser = require('body-parser')
const ejs = require('ejs')
// ********* must install body parser to use req.body **********
const mongoose = require('mongoose');
//removed when hashing
// const encrypt = require('mongoose-encryption');
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require('express-session')
const passport = require("passport");
const passportLocalmongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

// console.log(md5("123456"));
// console.log(process.env.API_KEY);
// console.log(process.env.SECRET);

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "My name is Bello.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


//Set up default mongoose connection
mongoose.connect('mongodb://127.0.0.1:27017/userDB', { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalmongoose);
userSchema.plugin(findOrCreate);


//encryption plugin- must be before model
// moved const to .env file so it is hidden
//removed when hashing
// console.log(process.env.SECRET);
// userSchema.plugin(encrypt, {
//     secret: process.env.SECRET,
//     encryptedFields: ['password'],
// });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id).then(function (user) {
        done(null, user);
    }).catch(function (err) {
        done(err);
    });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},

    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);

        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get('/', function (req, res) {
    res.render('home');
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

app.get('/login', function (req, res) {
    res.render('login');
});

app.get('/register', function (req, res) {
    res.render('register');
});

app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } })
        .then(foundUsers => {
            res.render("secrets", { usersWithSecrets: foundUsers });
        })
        .catch(err => {
            console.log(err);
        });
});


app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);

    User.findById(req.user.id)
        .then((foundUser) => {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                return foundUser.save();
            }
        })
        .then(() => {
            res.redirect("/secrets");
        })
        .catch((err) => {
            console.log(err);
        });

});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            console.log("Logout Successfully");
        }
    });

    res.redirect("/");
});

app.post("/register", function (req, res) {

    // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    //     //Store hash in your password DB.

    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });

    //     newUser.save()
    //         .then(() => {
    //             res.render("secrets");
    //         })
    //         .catch((err) => {
    //             console.log(err);
    //         });
    // });

    User.register({ username: req.body.username },
        req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate('local')(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        });

});

app.post("/login", function (req, res) {

    // const username = req.body.username;
    // const password = req.body.password;

    // User.findOne({ email: username })
    //     .then(foundUser => {
    //         console.log(foundUser);
    //         bcrypt.compare(password, foundUser.password)
    //             .then((result) => {
    //                 if (result === true) {
    //                     res.render("secrets");
    //                 }
    //             })
    //     })
    //     .catch(err => { console.log(err) })

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});


app.listen(3000, function () {
    console.log(`Server started at port 3000`);
});

// Note md5 level 3 is making it to be hash 