// src/middlewares/error/errorHandler.middleware.js

import ERRORS from "../../constants/errors.js";

const getCollectionName = (err) => {
	if (err.errorResponse?.collection) return err.errorResponse.collection;

	if (err.errorResponse?.ns) return err.errorResponse.ns.split('.')[1];

	const match = err.message?.match(/collection:\s+([^.]+)\.([^\s]+)/);
	if (match) return match[2];

	return "unknown";
};

const errorHandler = (err, req, res, next) => {
	const isProd = process.env.NODE_ENV === "production";

	// Debug logging
	if (!isProd) {
		console.error("🔥 ERROR:", err);
		if (err.stack) console.error(err.stack);
	}

	// -----------------------------------------
	// 1. Handle MongoDB Duplicate Key Error (E11000)
	// -----------------------------------------
	if (err.code === 11000) {
		const collection = getCollectionName(err);
		const fields = Object.keys(err.keyPattern).join(",");

		let message;
		if (collection === "polls") {
			message = ERRORS.POLL_ALREADY_EXISTS;
		} else{
			message = `${fields} already exists in ${collection}`;
		}

		return res.status(400).json({
			success: false,
			message
		});
	}

	// -----------------------------------------
	// 2. Handle Mongoose Validation Errors
	// -----------------------------------------
	if (err.name === "ValidationError") {
		const errors = Object.values(err.errors).map((v) => v.message);

		return res.status(400).json({
			success: false,
			message: errors.join(", ")
		});
	}

	// -----------------------------------------
	// 3. Handle Invalid ObjectId (CastError)
	// -----------------------------------------
	if (err.name === "CastError" && err.kind === "ObjectId") {
		return res.status(400).json({
			success: false,
			message: `Invalid ID: ${err.value}`
		});
	}

	// -----------------------------------------
	// 4. Handle JWT Errors
	// -----------------------------------------
	if (err.name === "JsonWebTokenError") {
		return res.status(401).json({
			success: false,
			message: "Invalid token"
		});
	}

	if (err.name === "TokenExpiredError") {
		return res.status(401).json({
			success: false,
			message: "Token expired, please login again"
		});
	}

	// -----------------------------------------
	// 5. Handle Syntax Error (bad JSON body)
	// -----------------------------------------
	if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
		return res.status(400).json({
			success: false,
			message: "Invalid JSON payload"
		});
	}

	// -----------------------------------------
	// 6. Custom ApiError instance
	// -----------------------------------------
	if (err.statusCode) {
		return res.status(err.statusCode).json({
			success: false,
			message: err.message,
			...(err.data && { data: err.data })
		});
	}

	// -----------------------------------------
	// 7. Fallback: internal server error
	// -----------------------------------------
	return res.status(500).json({
		success: false,
		message: isProd ? "Internal server error" : err.message,
	});
};

export default errorHandler;
