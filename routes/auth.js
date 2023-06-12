const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const jwt = require("jsonwebtoken");
const User = require('../models/user');
const { SECRET_KEY } = require("../config");


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post('/login', async(req, res, next) => {
	try{
		const { username, password } = req.body;
		if(!username || !password){
			throw new ExpressError('Please enter username and password', 400)
		}
		if (await User.authenticate(username, password)){
			const _token = jwt.sign({ username : username }, SECRET_KEY);
			User.updateLoginTimestamp(username)
			return res.json({ _token })
		}
		throw new ExpressError('Incorrect username/password.', 400)
	} catch(e){
		return next(e)
	}
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post('/register', async(req,res,next) => {
	try{
		const { username, password, first_name, last_name, phone } = req.body
		if(!username || !password || !first_name || !last_name || !phone){
			throw new ExpressError('Please enter all required information', 400)
		}
		const user = await User.register(req.body)
		const _token = jwt.sign({ username : user.username }, SECRET_KEY)
		User.updateLoginTimestamp(username)
		return res.json({ _token })
	} catch(e) {
		return next(e)
	}
})


module.exports = router