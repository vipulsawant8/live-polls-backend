import asyncHandler from "express-async-handler";
import User from "../models/user.model.js";
import ApiError from "../utils/ApiError.js";

import { setCookieOptions, clearCookieOptions } from "../constants/cookieOptions.js";

import ERRORS from "../constants/errors.js";

import jwt from 'jsonwebtoken';

const generateAccessRefreshToken = async ({ userId, deviceId, userAgent, ipAddress }) => {

	const user = await User.findById(userId);
	if (!user) throw new ApiError(404, "User Not Found");

	const accessToken = await user.generateAccessToken();
	const refreshToken = await user.generateRefreshToken();

	user.refreshTokens = user.refreshTokens.slice(-4);

	user.refreshTokens.push({
		token: refreshToken,
		deviceId,
		userAgent,
		ipAddress
	});
	
	await user.save({ validateBeforeSave: false });

	const tokens = { accessToken, refreshToken };
	return tokens;
};

const registerUser = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {

		console.log("registerUser Handler");
		console.log("req.body :", req.body);
	}

	const email = req.body.email;
	const name = req.body.name;
	const password = req.body.password;

	if (!email || !name || !password) throw new ApiError(400, ERRORS.MISSING_FIELDS);

	const user = await User.findOne({ email });
	if (user) throw new ApiError(400, ERRORS.EMAIL_ALREADY_EXISTS);

	const newUser = await User.create({ email, password, name });

	const userResponse = newUser.toJSON();

	const response = { message: "Account created successfully.", data: userResponse, success: true };
	return res.status(200).json(response);
} );

const loginUser = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {

		console.log("loginUser controller");
		console.log("req.body :", req.body);
	}

	const identity = req.body.identity;
	const password = req.body.password;
	const deviceId = req.body.deviceId;

	if (!identity || !password || !deviceId) throw new ApiError(400, ERRORS.MISSING_FIELDS);

	const validUser = await User.findOne({ email: identity }).select("-refreshToken");

	if (!validUser) throw new ApiError(401, ERRORS.INVALID_CREDENTIALS);

	if (process.env.NODE_ENV === "development") console.log('validUser :', validUser);

	const isPasswordVerified = await validUser.verifyPassword(password);

	if (!isPasswordVerified) throw new ApiError(401, ERRORS.INVALID_CREDENTIALS);

	const { accessToken, refreshToken } = await generateAccessRefreshToken({ userId: validUser._id, deviceId, userAgent: req.get('User-Agent') || '', ipAddress: req.ip });
	
	const responseUser = validUser.toJSON();

	const response = { message: "Logged in successfully.", data: responseUser, success: true };

	return res.status(200)
	.cookie('accessToken', accessToken, setCookieOptions('accessToken'))
	.cookie('refreshToken', refreshToken, setCookieOptions('refreshToken'))
	.json(response);
} );

const logoutUser = asyncHandler( async (req, res) => {

	const incomingToken = req.cookies.refreshToken;
	const deviceId = req.body.deviceId;

	const user = req.user;

	if (!incomingToken || !deviceId)  throw new ApiError(401, "Unauthorized");
	
	let decodedToken;
	try {
		decodedToken = jwt.verify(incomingToken, process.env.REFRESH_TOKEN_SECRET);
	} catch (error) {
		
		return res.status(401)
		.clearCookie('accessToken', clearCookieOptions('accessToken'))
		.clearCookie('refreshToken', clearCookieOptions('refreshToken'))
		.json({ message: "Unauthorized.", success: false });
	}
	
	// await User.findByIdAndUpdate(user._id, { $set: { refreshToken: null } });
	const userFromDb = await User.findById(user._id);

	if (userFromDb) {
		userFromDb.refreshTokens = userFromDb.refreshTokens.filter( tokenObj => tokenObj.deviceId !== deviceId );
		await userFromDb.save({ validateBeforeSave: false });
	}

	const response = { message: "Logged out successfully.", success: true };
	return res.status(200)
	.clearCookie('accessToken', clearCookieOptions('accessToken'))
	.clearCookie('refreshToken', clearCookieOptions('refreshToken'))
	.json(response);
} );

const getMe = asyncHandler( async (req, res) => {

	const user = req.user;
	
	const response = { message: "Profile loaded successfully.", data: user };

	return res.status(200).json(response);
} );

const refreshAccessToken = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {
		
		console.log("refresh controller");
		console.log("req.body :", req.body);
	}

	const incomingToken = req.cookies.refreshToken;
	const deviceId = req.body.deviceId;

	if (!incomingToken)  throw new ApiError(401, "Unauthorized");
	
	const decodedToken = jwt.verify(incomingToken, process.env.REFRESH_TOKEN_SECRET);

	if (!decodedToken || !decodedToken.id) throw new ApiError(401, "Unauthorized");

	const validUser = await User.findById(decodedToken.id);
	
	if (process.env.NODE_ENV === "development") console.log('validUser :', validUser);

	if (!validUser) throw new ApiError(404, "Unauthorized");

	const tokenIndex = validUser.refreshTokens.findIndex( (tokenObj) => tokenObj.token === incomingToken && tokenObj.deviceId === deviceId );

	if (tokenIndex === -1) {

		validUser.refreshTokens = [];
		await validUser.save({ validateBeforeSave: false });
		throw new ApiError(401, "Unauthorized");
	};
	
	validUser.refreshTokens.splice(tokenIndex, 1);
	await validUser.save({ validateBeforeSave: false });

	const { accessToken, refreshToken } = await generateAccessRefreshToken({ userId: validUser._id, deviceId, userAgent: req.get('User-Agent') || '', ipAddress: req.ip });

	const validUserJSON = validUser.toJSON();

	const response = { message: "Session extended successfully.", data: validUserJSON, success: true };

	return res.status(200)
	.cookie('accessToken', accessToken, setCookieOptions('accessToken'))
	.cookie('refreshToken', refreshToken, setCookieOptions('refreshToken'))
	.json(response);
} );

export { registerUser, loginUser, logoutUser, getMe, refreshAccessToken }; 