const isProd = process.env.NODE_ENV === "production";
	
const base = {
	secure: isProd,
	httpOnly: true,
	sameSite: isProd ? "none" : "lax"
};

const setCookieOptions = name => {
	const config = {
		accessToken: {
			...base,
			maxAge: 30 * 60 * 1000
		},
		refreshToken: {
			...base,
			maxAge: 15 * 24 * 60 * 60 * 1000
		}
	 };

	return config[name] || null;
};

const clearCookieOptions = name => {
	const config = {
		accessToken: {
			...base,
			maxAge: 0
		},
		refreshToken: {
			...base,
			maxAge: 0
		}
	 };

	return config[name] || null;
};


export { setCookieOptions, clearCookieOptions };