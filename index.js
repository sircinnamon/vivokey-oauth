let express = require("express");
let fs = require("fs")
let cookieParser = require("cookie-parser")
let { v4: uuidv4 } = require('uuid')
let bodyParser = require('body-parser')
let VivokeyOauth = require('./vivokey-oauth.js')
let app = express()

// https://www.vivokey.com/api

const PORT = 19933
app.listen(19933)
app.use(cookieParser())
app.use(bodyParser.json())
let creds = JSON.parse(fs.readFileSync(".creds"))
let known_users = {}
let known_keys = {}
let cached_states = {}

const vivokey_handler = new VivokeyOauth(creds)

function getJWTBody(jwt){
	if(!jwt){return {}}
	try {
		let s = jwt.split(".")
		let body = Buffer.from(s[1], "base64").toString()
		body = JSON.parse(body)
		return body
	} catch(err) {
		console.error(err)
		return {}
	}
}

app.get("/oauth/", (req, res) => {
	res.send("<a href='/oauth/login'>Log In</a>")
})
app.get("/oauth/login", (req, res) => {
	let redirect_url = encodeURIComponent(`https://mimir.sircinnamon.ca/oauth/rcv`)
	let scope = "openid%20profile%20email"
	return vivokey_handler.authRedirect(req, res, redirect_url, scope)
})
app.get("/oauth/rcv", (req, res) => {
	// console.log(req.query)
	let code = req.query.code
	let state = req.query.state
	let redirect_url = encodeURIComponent(`https://mimir.sircinnamon.ca/oauth/rcv`)
	let tokens;
	vivokey_handler.receiveCode(state, redirect_url, code)
	.then(ts => {
		tokens = ts
		return vivokey_handler.getInfo(ts.access_token)
	})
	.then(userinfo => {
		let uid = getJWTBody(tokens.id_token).sub // Unique user id
		known_users[uid] = {data: {verified: false, ...userinfo}, tokens: tokens} // Store known info
		res.set("Set-Cookie", `jwt=${tokens.id_token};`) // Set jwt for user
		res.set("Location", "/oauth/private") // Redirect to destination
		res.sendStatus(307)
	})
	.catch((err) => {
		console.error(err)
		console.error(err.response.data)
		res.status(500)
		res.send(err.response.data)
	})
})

app.get("/oauth/trigger-validate", async (req, res) => {
	let jwt = req.cookies.jwt
	if(await vivokey_handler.validateJWT(jwt)){ // Ensure user is logged in
		if(known_users[getJWTBody(jwt).sub]){ // Ensure we know this user
			let user = known_users[getJWTBody(jwt).sub]
			let access_token = user.tokens.access_token
			let body = {
				"message": "Test verification",
				"id": uuidv4(),
				"timeout": 60,
				"callback": "https://mimir.sircinnamon.ca/oauth/rcv-validate"
			}
			// Store request ID
			user.transactions = [body.id]
			known_users[getJWTBody(jwt).sub] = user
			// Trigger
			vivokey_handler.triggerValidate(access_token, body)
			.catch((err) => {
				console.error(err)
			})
		}
	}
	res.set("Location", "/oauth/private")
	res.sendStatus(307)
})

app.post("/oauth/rcv-validate", (req, res) => {
	// console.log(req)
	let body = vivokey_handler.receiveValidate(req.body)
	if(body.success){
		// Find user holding matching request ID
		for (let i = Object.keys(known_users).length - 1; i >= 0; i--) {
			let k = Object.keys(known_users)[i]
			let u = known_users[k]
			if(u.transactions && u.transactions.includes(body.id)){
				// Mark as verified
				u.data.verified = true
				known_users[k] = u
			}
		}
	}
})

app.get("/oauth/private", async (req, res) => {
	// console.log(req.cookies.jwt)
	let jwt = req.cookies.jwt
	if(await vivokey_handler.validateJWT(jwt)){
		let user = {
			data: {given_name: "Unknown", verified: false}
		}
		if(known_users[getJWTBody(jwt).sub]){
			user = known_users[getJWTBody(jwt).sub]
		}
		res.send(`This is private data. Welcome ${user.data.given_name}.<br>Verified: ${user.data.verified} <a href='/oauth/trigger-validate'>Verify</a>`)
	} else {
		res.status(401)
		res.send("You are not logged in. <a href='/oauth/login'>Log In</a>")
	}
})