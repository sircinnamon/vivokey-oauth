let express = require("express");
let fs = require("fs")
let axios = require("axios")
let cookieParser = require("cookie-parser")
let jwtlib = require("jsonwebtoken")
let jwksClient = require("jwks-rsa")
let { v4: uuidv4 } = require('uuid')
let bodyParser = require('body-parser')
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

const AUTH_ENDPOINT = "https://api.vivokey.com/openid/authorize/"
const TOKEN_ENDPOINT = "https://api.vivokey.com/openid/token/"
const INFO_ENDPOINT = "https://api.vivokey.com/openid/userinfo/"
const JWKS_ENDPOINT = "https://api.vivokey.com/openid/jwks/"
const VALIDATE_ENDPOINT = "https://api.vivokey.com/v1.0/validate/"

const ISSUER = "https://api.vivokey.com/openid"

async function validateJWT(jwt){
	// https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
	if(!jwt){return false}
	try {
		// console.log("BBB")
		let payload = await new Promise((resolve, reject) => {
			jwtlib.verify(jwt, getKey, {
				issuer: ISSUER,
				audience: creds.client_id,
				algorithms: ["HS256", "RS256"]
			},
			(err, payload) => {
				if(err){reject(err)}
				else{resolve(payload)}
			})
		})
		.then(payload => {
			// console.log("EEE")
			console.log(payload)
			return payload
		})
		.catch(err => {
			// console.log("DDD")
			console.error(err)
			return false
		})
		// console.log("CCC")
		if(!payload){return false}
		// console.log("AAA")
		return true;
	} catch(err) {
		console.error(err)
		return false
	}

}
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
async function getSigningKeys(){
	return axios.get(JWKS_ENDPOINT)
		.then(response => {
			return response.data
		})
		.catch(err => {
			console.error(err)
			return undefined;
		})
}

// function getKey(headers, callback){
// 	console.log(headers)
// 	getSigningKeys()
// 		.then(data => {
// 			let keys = data.keys
// 			for (var i = keys.length - 1; i >= 0; i--) {
// 				if(keys[i].kid == headers.kid){
// 					console.log(keys[i])
// 					let pem = Buffer.from(keys[i].n, "base64").toString("base64") // Convert to normal b64
// 					pem = pem.match(/.{1,64}/g).join("\n")
// 					pem = `-----BEGIN RSA PUBLIC KEY-----\n${pem}\n-----END RSA PUBLIC KEY-----\n`
// 					console.log(pem)
// 					callback(null, pem)
// 				}
// 			}
// 			callback(new Error("Not found"), null)
// 		})
// 		.catch(err => {callback(err, null)})
// }

function getKey(header, callback){
	client.getSigningKey(header.kid, (err, key) => {
		let signingKey = key.publicKey || key.rsaPublicKey
		callback(null, signingKey)
	})
}

function genState(){
	let stateString = uuidv4()
	cached_states[stateString] = Date.now()
	setTimeout(()=>{
		console.log("Login state expired")
		try{
			delete cached_states[stateString]
		} catch {
			// Do nothing
		}
	}, 120000)
	return stateString
}

app.get("/oauth/", (req, res) => {
	res.send("<a href='/oauth/login'>Log In</a>")
})
app.get("/oauth/login", (req, res) => {
	let redirect_url = encodeURIComponent(`https://mimir.sircinnamon.ca/oauth/rcv`)
	let scope = "openid%20profile%20email"
	let state = genState()
	let loc = `${AUTH_ENDPOINT}?response_type=code&client_id=${creds.client_id}&redirect_uri=${redirect_url}&scope=${scope}&state=${state}`
	res.set("Location", loc)
	res.sendStatus(307)
})
app.get("/oauth/rcv", (req, res) => {
	// console.log(req.query)
	if(!cached_states[req.query.state]){
		res.return(401)
	} else {
		delete cached_states[req.query.state]
	}
	let code = req.query.code
	let redirect_url = encodeURIComponent(`https://mimir.sircinnamon.ca/oauth/rcv`)
	let tokens;
	axios.request({
		method: "POST",
		url: `${TOKEN_ENDPOINT}`,
		data: `grant_type=authorization_code&code=${code}&redirect_uri=${redirect_url}`,
		auth: {username: creds.client_id, password: creds.client_secret},
		headers: {"Content-Type": "application/x-www-form-urlencoded"}
	})
	.then((response) => {
		console.log(response.data)
		// console.log(response.status)
		tokens = response.data
		return axios.request({
			method: "GET",
			url: `${INFO_ENDPOINT}`,
			headers: {"Authorization": `Bearer ${tokens.access_token}`}
		})
	})
	.then((userinfo) => {
		console.log(userinfo.data)
		// console.log(userinfo.status)
		let uid = getJWTBody(tokens.id_token).sub
		known_users[uid] = {data: {verified: false, ...userinfo.data}, tokens: tokens}
		res.set("Set-Cookie", `jwt=${tokens.id_token};`)
		res.set("Location", "/oauth/private")
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
	if(await validateJWT(jwt)){
		if(known_users[getJWTBody(jwt).sub]){
			let user = known_users[getJWTBody(jwt).sub]
			let access_token = user.tokens.access_token
			let body = {
				"message": "Test verification",
				"id": uuidv4(),
				"timeout": 60,
				"callback": "https://mimir.sircinnamon.ca/oauth/rcv-validate"
			}
			user.transactions = [body.id]
			known_users[getJWTBody(jwt).sub] = user
			axios.request({
				method: "post",
				url: `${VALIDATE_ENDPOINT}`,
				headers: {"Authorization": `Bearer ${access_token}`},
				data: body
			})
			.then((resp) => {
				console.log(resp.data)
				console.log(resp.status)
				console.log("AAA")
				console.log(resp)
			})
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
	console.log(req.body)
	if(req.body.success){
		for (let i = Object.keys(known_users).length - 1; i >= 0; i--) {
			let k = Object.keys(known_users)[i]
			let u = known_users[k]
			if(u.transactions && u.transactions.includes(req.body.id)){
				u.data.verified = true
				known_users[k] = u
			}
		}
	}
})

app.get("/oauth/private", async (req, res) => {
	// console.log(req.cookies.jwt)
	let jwt = req.cookies.jwt
	if(await validateJWT(jwt)){
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

// getSigningKeys()
// 	.then(keys => {
// 		if(keys){known_keys = keys}
// 	})

let client = jwksClient({
	strictSsl: true,
	jwksUri: JWKS_ENDPOINT
})