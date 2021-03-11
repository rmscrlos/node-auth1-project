const express = require('express');
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');

const router = express.Router();

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/api/auth/register', async (req, res, next) => {
	try {
		const { username, password } = req.body;
		const user = await Users.findBy({ username }).first();

		if (user) {
			return res.status(422).json({
				message: 'Username taken.'
			});
		}

		if (password <= 3) {
			return res.status(422).json({
				message: 'Password must be longer than 3 chars.'
			});
		}

		const newUser = await Users.add({
			username,
			password: await bcrypt.hash(password, 14)
		});

		res.status(201).json(newUser);
	} catch (err) {
		next(err);
	}
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/api/auth/login', async (req, res, next) => {
	try {
		const { username, password } = req.body;
		const user = await Users.findBy({ username }).first();

		const passwordValid = await bcrypt.compare(password, user ? user.password : '');

		if (!user || !passwordValid) {
			return res.status(401).json({
				message: 'Invalid credentials.'
			});
		}

		req.session.user = user;

		res.json({
			message: `Welcome ${user.username}`
		});
	} catch (err) {
		next(err);
	}
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get('/api/auth/logout', async (req, res, next) => {
	try {
		req.session.destroy(err => {
			if (err) {
				next(err);
			} else {
				res.status(204).end();
			}
		});
	} catch (err) {
		next(err);
	}
});

// Don't forget to add the router to the `exports` object so it can be required in other modules
