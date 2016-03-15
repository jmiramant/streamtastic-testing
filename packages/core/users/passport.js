'use strict';

var mongoose = require('mongoose'),
  LocalStrategy = require('passport-local').Strategy,
  GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
  User = mongoose.model('User'),
  config = require('meanio').loadConfig();

module.exports = function(passport) {
  // Serialize the user id to push into the session
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  // Deserialize the user object based on a pre-serialized token
  // which is the user id
  passport.deserializeUser(function(id, done) {
    User.findOne({
      _id: id
    }, '-salt -hashed_password', function(err, user) {
      done(err, user);
    });
  });

  // Use local strategy
  passport.use(new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password'
    },
    function(email, password, done) {
      User.findOne({
        email: email
      }, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, {
            message: 'Unknown user'
          });
        }
        if (!user.authenticate(password)) {
          return done(null, false, {
            message: 'Invalid password'
          });
        }
        return done(null, user);
      });
    }
  ));

  // Use google strategy
  passport.use(new GoogleStrategy({
      clientID: config.strategies.google.clientID,
      clientSecret: config.strategies.google.clientSecret,
      callbackURL: config.strategies.google.callbackURL
    },
    function(accessToken, refreshToken, profile, done) {
      User.findOne({
        'google.id': profile.id
      }, function(err, user) {
        if (user) {
          if (user.hasPermission()) {
            return done(err, user);
          } else {
            return done(null, false, {message: 'This email server is not authorize to access this application. Please contact Sean at murphsp1@gmail.com'});
          }
        }
        user = new User({
          name: profile.displayName,
          email: profile.emails[0].value,
          username: profile.emails[0].value,
          provider: 'google',
          google: profile._json,
          roles: ['authenticated']
        });
        user.save(function(err) {
          if (err) {
            return done(null, false, {message: 'Google login failed, email already used by other login strategy'});
          } else {
            if (user.hasPermission()) {
              return done(err, user);
            } else {
              return done(null, false, {message: 'This email server is not authorize to access this application. Please contact Sean at murphsp1@gmail.com'});
            }
          }
        });
      });
    }
  ));

  return passport;
};
