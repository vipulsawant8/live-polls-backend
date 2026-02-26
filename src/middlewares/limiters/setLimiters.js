import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import ApiError from "../../utils/ApiError.js";

const createLimiter = (windowMs, max, message, keyType = "ip") =>
	rateLimit({
		windowMs,
		max,
		keyGenerator: (req) => {
			if (keyType === "email" && req.body?.email) {
				return req.body.email;
			}
			const key = ipKeyGenerator(req.ip);
			// console.log("Rate limit key:", key);
			// Safe IPv6-compatible IP handling
			console.log("Instance PID:", process.pid);
			console.log("Generated key:", ipKeyGenerator(req.ip));
			return key;
		},
		handler: (req, res, next) =>
			next(new ApiError(429, message)),
		standardHeaders: true,
		legacyHeaders: false,
	});

export const createdUserLimiter = createLimiter(
	15 * 60 * 1000,
	5,
	"Too many registration attempts. Try again later."
);

export const verifyEmailLimiter = createLimiter(
	15 * 60 * 1000,
	20,
	"Too many verification attempts. Try again later."
);

export const loginLimiter = createLimiter(
	15 * 60 * 1000,
	5,
	"Too many login attempts. Try again later.",
    "email"
);

export const forgotPasswordLimiter = createLimiter(
	60 * 60 * 1000,
	5,
	"Too many reset requests. Please try again later.",
    "email"
);

export const resetPasswordLimiter = createLimiter(
	60 * 60 * 1000,
	10,
	"Too many reset requests. Please try again later."
);

export const changePasswordLimiter = createLimiter(
	15 * 60 * 1000,
	5,
	"Too many password change attempts."
);

export const refreshTokenLimiter = createLimiter(
	15 * 60 * 1000,
	20,
	"Too many token refresh attempts. Please try again later."
);