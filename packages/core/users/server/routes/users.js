'use strict';

var config = require('meanio').loadConfig();
var jwt = require('jsonwebtoken'); //https://npmjs.org/package/node-jsonwebtoken

module.exports = function(MeanUser, app, auth, database, passport) {

  // User routes use users controller
  var users = require('../controllers/users')(MeanUser);

  app.route('/api/logout')
    .get(users.signout);
  app.route('/api/users/me')
    .get(users.me);

  // Setting up the userId param
  app.param('userId', users.user);

  // AngularJS route to check for authentication
  app.route('/api/loggedin')
    .get(function(req, res) {
      if (!req.isAuthenticated()) return res.send('0');
      auth.findUser(req.user._id, function(user) {
        res.send(user ? user : '0');
      });
    });

  if (config.strategies.local.enabled) {
    // Setting up the users api
    app.route('/api/register')
      .post(users.create);

    app.route('/api/forgot-password')
      .post(users.forgotpassword);

    app.route('/api/reset/:token')
      .post(users.resetpassword);

    // Setting the local strategy route
    app.route('/api/login')
      .post(passport.authenticate('local', {
        failureFlash: false
      }), function(req, res) {
        var payload = req.user;
        payload.redirect = req.body.redirect;
        var escaped = JSON.stringify(payload);
        escaped = encodeURI(escaped);
        // We are sending the payload inside the token
        var token = jwt.sign(escaped, config.secret, {
          expiresInMinutes: 60 * 5
        });
        MeanUser.events.publish({
          action: 'logged_in',
          user: {
            name: req.user.name
          }
        });
        res.json({
          token: token,
          redirect: config.strategies.landingPage
        });
      });
  }

  // AngularJS route to get config of social buttons
  app.route('/api/get-config')
    .get(function(req, res) {
      // To avoid displaying unneccesary social logins
      var strategies = config.strategies;
      var configuredApps = {};
      for (var key in strategies) {
        if (strategies.hasOwnProperty(key)) {
          var strategy = strategies[key];
          if (strategy.hasOwnProperty('enabled') && strategy.enabled === true) {
            configuredApps[key] = true;
          }
        }
      }
      res.send(configuredApps);
    });

  if (config.strategies.google.enabled) {
    // Setting the google oauth routes
    app.route('/api/auth/google')
      .get(passport.authenticate('google', {
        failureRedirect: '/auth/login',
        failureFlash: true,
        scope: [
          'https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/userinfo.email'
        ]
      }), users.signin);

    var googleInvalidationRedirect = 'https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout?continue=' + config.hostname + '/auth/login'

    app.route('/api/auth/google/callback')
      .get(passport.authenticate('google', {
        failureRedirect: googleInvalidationRedirect
      }), users.authCallback);
  }
};