const express = require("express");
const router = new express.Router();
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");
const Message = require('../models/message');
const jwt = require("jsonwebtoken");
const ExpressError = require("../expressError");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get('/:id', ensureLoggedIn, async (req, res, next) => {
	try{
		const currUsername = req.user.username
		const msg = await Message.get(req.params.id)
		
		if(!(msg.from_user.username === currUsername 
			|| msg.to_user.username === currUsername)){
				throw new ExpressError("Unauthorized", 401)
		}
		return res.json(msg)
	} catch(e){
		return next(e)
	}
} )

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', ensureLoggedIn, async(req,res,next) => {
	try{
		const from_username = req.user.username
		const { to_username, body } = req.body;
		const message = await Message.create(from_username, to_username, body)
		return res.json({ message })
	} catch(e){
		return next(e)
	}
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
router.post('/:id/read', ensureLoggedIn, async(req, res, next) => {
	try{
		const msgId = req.params.id
		const currUsername = req.user.username;
		const msg = await Message.get(msgId)
		if(msg.to_user.username != currUsername){
			throw new ExpressError("Unauthorized", 400)
		}
		const message = await Message.markRead(msgId)
		return res.json({ message })
	} catch(e){
		return next(e)
	}
})

module.exports = router