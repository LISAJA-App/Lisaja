// --------------------------------------------------- //
// VAR AND CONS TABLE STARTUP //
// --------------------------------------------------- //
var express = require("express"),
    app = express(),
    mongoose = require("mongoose"),
    passport = require("passport"),
    bodyParser = require("body-parser"),
    User = require("./models/user_new_new"),
    cookieParser = require('cookie-parser'),
    session = require('express-session'),
    port = process.env.PORT || 8080;

//passportLocalMongoose = require("passport-local-mongoose")
//LocalStrategy = require("passport-local"),

const https = require('https'),
    fs = require('fs')

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //

mongoose.connect("mongodb://localhost/authapp");

// --------------------------------------------------- //
// SECRET PAGE BODY PARSER //
// --------------------------------------------------- //

app.use(bodyParser.urlencoded({ extended: true }));
app.use(require("express-session")({
    secret: "Rusty is the best og in the world",
    resave: false,
    saveUninitialized: false
}));

// --------------------------------------------------- //
// INITIALIZE EXPRESS //
// --------------------------------------------------- //

app.set('view engine', 'ejs');
app.use(express.static('public'))

// --------------------------------------------------- //
// INITIALIZE BODYPARSER AS MIDDLEWARE //
// --------------------------------------------------- //

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //

app.use(session({
    secret: 'secret',
    saveUninitialized: true,
    resave: true
}));

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //

app.use(passport.initialize());
app.use(passport.session());

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
// Register User

app.post('/register', function(req, res) {
    var password = req.body.password;
    var password2 = req.body.password2;

    if (password == password2) {
        var newUser = new User({
            name: req.body.name,
            email: req.body.email,
            username: req.body.username,
            password: req.body.password
        });

        User.createUser(newUser, function(err, user) {
            if (err) throw err;
            //res.send(user).end()

            passport.authenticate("local")(req, res, function() {
                res.redirect("/secret"); //once the user sign up
            });
        });
    }
    else {
        res.status(500).send({ error: "Passwords don't match" }).end()
        console.log("falsches Passwort")
    }
});

// --------------------------------------------------- //
// DRINKING //
// --------------------------------------------------- //

app.post('/drinking', function(req, res, next) {

    console.log(req.user._id)

    User.update({ _id: req.user._id }, {
        $set: {
            userWeight: req.body.weight,
            lastDateChange: new Date().getDate()
        }
    }, function(err) {
        if (err) console.log(err);
        res.render('pages/drinking', {
            user: req.user
        });
    });
    res.redirect('/drinking');
});

app.post('/lastDrink', function(req, res, next) {

    console.log(req.user._id)

    var drinkingCounterNumber = req.user.drinkingCounter;
    drinkingCounterNumber += 1;

    if (req.user.lastDateDrinked < req.body.lastDate) {
        drinkingCounterNumber = 0;
    }

    User.update({ _id: req.user._id }, {
        $set: {
            lastTimeDrinked: req.body.lastTime,
            lastDateDrinked: req.body.lastDate,
            drinkingCounter: drinkingCounterNumber,
            lastDateChange: new Date().getDate()
        }
    }, function(err) {
        if (err) console.log(err);
        res.render('pages/drinking', {
            user: req.user
        });
    });
    res.redirect('/drinking');
});

// --------------------------------------------------- //
// CALENDAR //
// --------------------------------------------------- //

app.post('/calendar', function(req, res, next) {

    console.log(req.user._id)

    User.update({ _id: req.user._id }, {
        $set: {
            currentPeriod: req.body.period,
            lastDateChange: new Date().getDate()
        }
    }, function(err) {
        if (err) console.log(err);
        res.render('pages/calendar', {
            user: req.user
        });
    });
    res.redirect('/calendar');
});

// --------------------------------------------------- //
// TRACKER //
// --------------------------------------------------- //

app.post('/jogging', function(req, res, next) {

    console.log(req.user._id)

    if (req.body.JoggingBegin > "") {
        User.update({ _id: req.user._id }, {
            $set: {
                joggingStart: req.body.JoggingBegin,
                lastDateChange: new Date().getDate()
            }
        }, function(err) {
            if (err) console.log(err);
            res.render('pages/tracker', {
                user: req.user
            });
        });
    } else {
        User.update({ _id: req.user._id }, {
            $set: {
                joggingStop: req.body.JoggingEnd,
                lastDateChange: new Date().getDate()
            }
        }, function(err) {
            if (err) console.log(err);
            res.render('pages/tracker', {
                user: req.user
            });
        });
    }
    res.redirect('/tracker');
}, function(req, res) {
    res.send(req.user)
});

app.post('/cycling', function(req, res, next) {

    console.log(req.user._id)

    if (req.body.CyclingBegin > "") {
        User.update({ _id: req.user._id }, {
            $set: {
                cyclingStart: req.body.CyclingBegin,
                lastDateChange: new Date().getDate()
            }
        }, function(err) {
            if (err) console.log(err);
            res.render('pages/tracker', {
                user: req.user
            });
        });
    } else {
        User.update({ _id: req.user._id }, {
            $set: {
                cyclingStop: req.body.CyclingEnd,
                lastDateChange: new Date().getDate()
            }
        }, function(err) {
            if (err) console.log(err);
            res.render('pages/tracker', {
                user: req.user
            });
        });
    }
    res.redirect('/tracker');
});

app.post('/strenghten', function(req, res, next) {

    console.log(req.user._id)

    if (req.body.StrenghtenBegin > "") {
        User.update({ _id: req.user._id }, {
            $set: {
                strenghtenStart: req.body.StrenghtenBegin,
                lastDateChange: new Date().getDate()
            }
        }, function(err) {
            if (err) console.log(err);
            res.render('pages/tracker', {
                user: req.user
            });
        });
    } else {
        User.update({ _id: req.user._id }, {
            $set: {
                strenghtenStop: req.body.StrenghtenEnd,
                lastDateChange: new Date().getDate()
            }
        }, function(err) {
            if (err) console.log(err);
            res.render('pages/tracker', {
                user: req.user
            });
        });
    }
    res.redirect('/tracker');
});

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //

// Using LocalStrategy with passport
var LocalStrategy = require('passport-local').Strategy;
passport.use(new LocalStrategy(
    function(username, password, done) {
        User.getUserByUsername(username, function(err, user) {
            if (err) throw err;
            if (!user) {
                return done(null, false, { message: 'Unknown User' });
            }

            User.comparePassword(password, user.password, function(err, isMatch) {
                if (err) throw err;
                if (isMatch) {
                    return done(null, user);
                }
                else {
                    return done(null, false, { message: 'Invalid password' });
                }
            });
        });
    }
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.getUserById(id, function(err, user) {
        done(err, user);
    });
});

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
// Init Webpage

app.get("/", function(req, res) {
    res.render("pages/home");
});

app.get("/secret", isLoggedIn, function(req, res) {
    res.render("pages/secret");
});

app.get("/calendar", isLoggedIn, function(req, res) {
    res.render("pages/calendar", { user: req.user });
});

app.get("/drinking", isLoggedIn, function(req, res) {
    //res.render("pages/drinking");
    res.render("pages/drinking", { user: req.user });
});

app.get("/tracker", isLoggedIn, function(req, res) {
    res.render("pages/tracker", { user: req.user });
});

app.get("/recipe1", isLoggedIn, function(req, res) {
    res.render("pages/recipe1");
});

app.get("/recipe2", isLoggedIn, function(req, res) {
    res.render("pages/recipe2");
});

app.get("/recipe3", isLoggedIn, function(req, res) {
    res.render("pages/recipe3");
});

app.get("/recipe4", isLoggedIn, function(req, res) {
    res.render("pages/recipe4");
});

app.get("/recipes", isLoggedIn, function(req, res) {
    res.render("pages/recipes");
});

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
// Auth Routes

app.get("/register", function(req, res) {
    res.render("pages/register");
});

app.get("/login", function(req, res) {
    res.render("pages/login");
})

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        if ((req.user.lastDateChange - new Date().getDate()) == 0) {
            
        } else {
            User.update({ _id: req.user._id }, {
            $set: {
                lastTimeDrinked: "",
                lastDateDrinked: 0,
                drinkingCounter: 0,
                joggingStart: "",
                joggingStop: "",
                cyclingStart: "",
                cyclingStop: "",
                strenghtenStart: "",
                strenghtenStop: ""
            }
            }, function(err) {
                if (err) console.log(err);
                res.render('pages/login', {
                    user: req.user
                });
            });
        }
        return next();
    }
    res.redirect("/login");
}

// Endpoint to login
app.post('/login',
    passport.authenticate('local', {
        successRedirect: "/secret",
        failureRedirect: "/login"
    }),
    function(req, res) {
        res.send(req.user.id)
    }
);

// Endpoint to get current user
app.get('/user', function(req, res) {
    res.send(req.user);
})

// Endpoint to logout
app.get('/logout', function(req, res) {
    req.logout();
    //res.send(null);
    res.redirect("/");
});

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
// Facebook Auth
var FacebookStrategy = require('passport-facebook').Strategy;
passport.use(new FacebookStrategy({
        clientID: "836961773344468",
        clientSecret: "d80fc5a8bb0b5b5d034f45ea7efae03a",
        callbackURL: "https://ec2-52-201-123-197.compute-1.amazonaws.com:8080/auth/facebook/callback"
    },
    function(accessToken, refreshToken, profile, done) {
        console.log(profile)
        User.findOne({ 'facebook.id': profile.id }, function(err, user) {
            if (err) return done(err);
            if (user) return done(null, user);
            else {
                // if there is no user found with that facebook id, create them
                var newUser = new User();

                // set all of the facebook information in our user model
                newUser.facebook.id = profile.id;
                newUser.facebook.token = accessToken;
                newUser.facebook.name = profile.displayName;
                if (typeof profile.emails != 'undefined' && profile.emails.length > 0)
                    newUser.facebook.email = profile.emails[0].value;

                // save our user to the database
                newUser.save(function(err) {
                    if (err) throw err;
                    return done(null, newUser);
                });
            }
        });
    }
));

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        console.log(req.user)
        res.redirect('/secret');
    }
);

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
/* Google Auth
var passport = require('passport');
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

// Use the GoogleStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Google
//   profile), and invoke a callback with a user object.
passport.use(new GoogleStrategy({
        clientID: "945743340883-m2od3ujh1sufpfqkutd00ish507okvc7.apps.googleusercontent.com",
        clientSecret: "nfZw0nJjYVAcOyXfPK5OIjx3",
        callbackURL: '/auth/google/callback'
    },
    function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ googleId: profile.id }, function(err, user) {
            return done(err, user);
        });
    }
));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['https://www.googleapis.com/auth/plus.login'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
    }); */


// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
// Code to handle service worker & install prompt on desktop

/*('serviceWorker' in navigator) {
  navigator.serviceWorker
           .register('service-worker.js')
           .then(function() { console.log('Service Worker Registered'); });
}


let deferredPrompt;
const addBtn = document.querySelector('.add-button');
addBtn.style.display = 'none';

window.addEventListener('beforeinstallprompt', (e) => {
  // Prevent Chrome 67 and earlier from automatically showing the prompt
  e.preventDefault();
  // Stash the event so it can be triggered later.
  deferredPrompt = e;
  // Update UI to notify the user they can add to home screen
  addBtn.style.display = 'block';

  addBtn.addEventListener('click', (e) => {
    // hide our user interface that shows our A2HS button
    addBtn.style.display = 'none';
    // Show the prompt
    deferredPrompt.prompt();
    // Wait for the user to respond to the prompt
    deferredPrompt.userChoice
      .then((choiceResult) => {
        if (choiceResult.outcome === 'accepted') {
          console.log('User accepted the A2HS prompt');
        } else {
          console.log('User dismissed the A2HS prompt');
        }
        deferredPrompt = null;
      });
  });
});*/

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
// INITIALIZE HTTPS SERVER WITH PORT 8080 //
https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
}, app).listen(8080);

// --------------------------------------------------- //
// CONNECT TO MONGODB //
// --------------------------------------------------- //
console.log('Listening...');
