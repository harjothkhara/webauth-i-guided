
//middleware - can use for any endpoint we want to restrict to passing the valid credentials

const bcrypt = require('bcryptjs'); //<<<<<<<<<< we get the hash by using(importing) the bcryptjs library <<<<< yarn add bcryptjs

const Users = require('../users/users-model.js'); //interacting with our db


function protected(req, res, next) {
    const { username, password } = req.headers; //no body on GET...i'm going to read from the headers to see if username and password are there
  
  if (username && password) { //if username and password are there
        // next(); //go ahead
        Users.findBy({ username })
          .first()
          .then(user => {
            // if we do have a user, we found it by username, i want to check for the hash(syncronously), with the password guess against 
            // what the password has in the database. its going to take the guessed password, rehash it, and compare automatically 
            // with what is in the db.
            if (user && bcrypt.compareSync(password, user.password)) {
                                          //guess+rehash //we have in the db
            next(); //goes to next middleware (route handler) on a successful login with the correct credentials 
            } else {
              res.status(401).json({ message: 'Invalid Credentials' });
              // if we don't find the user by the username or if the password don't match we're still returning invalid credentials.
              //return unauthorized with a 401 instead of being specific and telling exactly what is invalid, because we want to keep them guessing
            }
          })
          .catch(error => {
            res.status(500).json(error);
          });
      } else { //if not
        res.status(400).json({ message: 'Please provide credentials'});
      }
  }

  module.exports = protected;