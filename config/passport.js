// config/passport.js

// load all the things we need
var LocalStrategy   = require('passport-local').Strategy;

// load up the user model
var User            = require('../app/models/user');

// expose this function to our app using module.exports
module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with identifiant
        usernameField : 'identifiant',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, identifiant, password, done) {

        // asynchronous
        // User.findOne wont fire unless data is sent back
        process.nextTick(function() {

        // find a user whose identifiant is the same as the forms identifiant
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'local.identifiant' :  identifiant }, function(err, user) {
            // if there are any errors, return the error
            if (err)
                return done(err);

            // check to see if theres already a user with that identifiant
            if (user) {
                return done(null, false, req.flash('signupMessage', 'Cet identifiant existe déjà.'));
            } else {

                // if there is no user with that identifiant
                // create the user
                var newUser            = new User();

                // set the user's local credentials
                newUser.local.identifiant    = identifiant;
                newUser.local.password = newUser.generateHash(password);

                // save the user
                newUser.save(function(err) {
                    if (err)
                        throw err;
                    return done(null, newUser);
                });
            }

        });    

        });

    }));
	
	
	// =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with identifiant
        usernameField : 'identifiant',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, identifiant, password, done) { // callback with identifiant and password from our form

        // find a user whose identifiant is the same as the forms identifiant
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'local.identifiant' :  identifiant }, function(err, user) {
            // if there are any errors, return the error before anything else
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'Utilisateur inconnu.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Mauvais mot de passe.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            return done(null, user);
        });

    }));
	
	
	
	// =========================================================================
    // LOCAL SIGNUP AUTHORIZATION =============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-signup_authorization', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with identifiant
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, password, done) { // callback with identifiant and password from our form

        // find a user whose identifiant is the same as the forms identifiant
        // we are checking to see if the user trying to login already exists
        // User.findOne({ 'local.ID' :  ID }, function(err, user) {
            // if there are any errors, return the error before anything else
            // if (err)
               // return done(err);

            // if no user is found, return the message
            // if (!user)
               // return done(null, false, req.flash('signup_authorizationMessage', 'Utilisateur inconnu.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            // if (!user.validPassword(password))
				// return done(null, false, req.flash('signup_authorizationMessage', 'Oops! Mauvais mot de passe.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            return done(null, user);
        // });

    }));

};


