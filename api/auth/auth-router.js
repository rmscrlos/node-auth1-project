const express = require('express');
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware');
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
router.post('/api/auth/register', checkUsernameFree(), checkPasswordLength(), async (req, res, next) => {
	try {
		const { username, password } = req.body;
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
router.post('/api/auth/login', checkUsernameExists(), async (req, res, next) => {
	try {
		req.session.user = req.user;
		console.log(req.user);
		res.json({
			message: `Welcome ${req.user.username}`
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
		if (!req.session.user) {
			return res.status(200).json({
				message: 'No session.'
			});
		}

		req.session.destroy(err => {
			if (err) {
				next(err);
			} else {
				res.status(200)
					.json({
						message: 'Logged out.'
					})
					.end();
			}
		});
	} catch (err) {
		next(err);
	}
});

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;
