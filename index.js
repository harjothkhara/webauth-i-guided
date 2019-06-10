const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs'); //<<<<<<<<<< we get the hash by using(importing) the bcryptjs library <<<<< yarn add bcryptjs

const db = require('./database/dbConfig.js'); //db config options - connections
const Users = require('./users/users-model.js'); //interacting with our db
const protected = require('./auth/protected-middleware.js'); //create new folder for middleware function

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body; //user credentials
  // check for username and password

  const hash = bcrypt.hashSync(user.password, 10); // 2^10 rounds <<<<<<<<<<<<<<<<<<<<<<<<< will generate our hash
  // pass > hashit > hash > hashit > hash > hashit > hash
  //we get the hash by using the bcryptjs library, has a few methods 1) hash(async) 2) hashsync
  //hash the password. goal:over-riding the pw that we get with the new hash before we save the user
  user.password = hash; //<<<<<<<<<<<<<<<<<<<<<<<< overriding the password of the user with the hash

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;
//username and password guess being sent in the request body by the client

//make a check for the password - library 
// we compare the password guess against the database hash  
Users.findBy({ username })
    .first()
    .then(user => {
      // if we do have a user, we found it by username, i want to check for the hash(syncronously), with the password guess against 
      // what the password has in the database. its going to take the guessed password, rehash it, and compare automatically 
      // with what is in the db.
      if (user && bcrypt.compareSync(password, user.password)) {
                                     //guess+rehash //we have in the db
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
        // if we don't find the user by the username or if the password don't match we're still returning invalid credentials.
        //return unauthorized with a 401 instead of being specific and telling exactly what is invalid, because we want to keep them guessing
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// protect this route, users must provide valid credentials to see the list of users
server.get('/api/users', protected, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});


const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));


