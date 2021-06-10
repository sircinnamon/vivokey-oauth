let axios = require("axios")
let { v4: uuidv4 } = require('uuid')
let jwksClient = require("jwks-rsa")
let jwtlib = require("jsonwebtoken")

module.exports = class VivokeyOauth {
	constructor(creds) {
		this.creds = creds

		this.AUTH_ENDPOINT = "https://api.vivokey.com/openid/authorize/"
		this.TOKEN_ENDPOINT = "https://api.vivokey.com/openid/token/"
		this.INFO_ENDPOINT = "https://api.vivokey.com/openid/userinfo/"
		this.JWKS_ENDPOINT = "https://api.vivokey.com/openid/jwks/"
		this.VALIDATE_ENDPOINT = "https://api.vivokey.com/v1.0/validate/"

		this.ISSUER = "https://api.vivokey.com/openid"

		this.cached_states = {}

		this.jwks_client = jwksClient({
			strictSsl: true,
			jwksUri: this.JWKS_ENDPOINT
		})
	}

	getKey(header, callback) {
		this.jwks_client.getSigningKey(header.kid, (err, key) => {
			let signingKey = key.publicKey || key.rsaPublicKey
			callback(null, signingKey)
		})
	}

	async validateJWT(jwt){
		// https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
		if(!jwt){return false}
		try {
			// console.log("BBB")
			let payload = await new Promise((resolve, reject) => {
				jwtlib.verify(jwt, this.getKey.bind(this), {
					issuer: this.ISSUER,
					audience: this.creds.client_id,
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

	getJWTBody(jwt) {
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

	genState() {
		let stateString = uuidv4()
		this.cached_states[stateString] = Date.now()
		setTimeout(()=>{
			console.log("Login state expired")
			try{
				delete this.cached_states[stateString]
			} catch {
				// Do nothing
			}
		}, 120000)
		return stateString
	}

	authRedirect(req, res, redirect_url, scope) {
		let state = this.genState()
		let loc = `${this.AUTH_ENDPOINT}?response_type=code&client_id=${this.creds.client_id}&redirect_uri=${redirect_url}&scope=${scope}&state=${state}`
		res.set("Location", loc)
		res.sendStatus(307)
	}

	async receiveCode(state, redirect_url, code) {
		// Convert received code to tokens
		if(!this.cached_states[state]){
			return Promise.reject("State invalid or expired.")
		} else {
			delete this.cached_states[state]
		}
		let tokens;
		return axios.request({
			method: "POST",
			url: `${this.TOKEN_ENDPOINT}`,
			data: `grant_type=authorization_code&code=${code}&redirect_uri=${redirect_url}`,
			auth: {username: this.creds.client_id, password: this.creds.client_secret},
			headers: {"Content-Type": "application/x-www-form-urlencoded"}
		})
		.then((response) => {
			console.log(response.data)
			// console.log(response.status)
			return response.data
		})
	}

	async getInfo(access_token) {
		return axios.request({
			method: "GET",
			url: `${this.INFO_ENDPOINT}`,
			headers: {"Authorization": `Bearer ${access_token}`}
		})
		.then((userinfo) => {
			console.log(userinfo.data)
			// console.log(userinfo.status)
			return userinfo.data
		})
	}

	async triggerValidate(access_token, body) {
		return axios.request({
			method: "post",
			url: `${this.VALIDATE_ENDPOINT}`,
			headers: {"Authorization": `Bearer ${access_token}`},
			data: body
		})
		.then((resp) => {
			console.log(resp.data)
			console.log(resp.status)
			console.log("AAA")
			console.log(resp)
			return resp
		})
	}

	receiveValidate(body) {
		if(!body.success){
			console.error(body.message)
		}
		return {success: body.success, id: body.id}
	}
}