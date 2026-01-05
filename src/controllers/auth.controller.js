import asyncHandler from "express-async-handler";
import User from "../models/user.model.js";
import ApiError from "../utils/ApiError.js";

import setCookieOptions from "../constants/setCookieOptions.js";
import ERRORS from "../constants/errors.js";

import jwt from 'jsonwebtoken';

const generateAccessRefreshToken = async (id) => {

	const user = await User.findById(id);
	if (!user) throw new ApiError(404, ERRORS.USER_NOT_FOUND);

	const accessToken = await user.generateAccessToken();
	const refreshToken = await user.generateRefreshToken();
	user.refreshToken = refreshToken;
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

	const response = { message: "User registred", data: userResponse, success: true };
	return res.status(200).json(response);
} );

const loginUser = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {

		console.log("loginUser controller");
		console.log("req.body :", req.body);
	}

	const identity = req.body.identity;
	const password = req.body.password;

	if (!identity || !password) throw new ApiError(400, ERRORS.MISSING_FIELDS);

	const validUser = await User.findOne({ email: identity }).select("-refreshToken");

	if (!validUser) throw new ApiError(401, ERRORS.INVALID_CREDENTIALS);

	// console.log('validUser :', validUser);

	const isPasswordVerified = await validUser.verifyPassword(password);

	if (!isPasswordVerified) throw new ApiError(401, ERRORS.INVALID_CREDENTIALS);

	const { accessToken, refreshToken } = await generateAccessRefreshToken(validUser._id);
	
	const responseUser = validUser.toJSON();

	const response = { message: "User logged-in successfully", data: responseUser, success: true };

	return res.status(200)
	.cookie('accessToken', accessToken, setCookieOptions('accessToken'))
	.cookie('refreshToken', refreshToken, setCookieOptions('refreshToken'))
	.json(response);
} );

const logoutUser = asyncHandler( async (req, res) => {

	const user = req.user;

	await User.findByIdAndUpdate(user._id, { $set: { refreshToken: null } });

	const response = { message: "User logged-out successfully", success: true };

	return res.status(200)
	.clearCookie('accessToken')
	.clearCookie('refreshToken')
	.json(response);
} );

const getMe = asyncHandler( async (req, res) => {

	const user = req.user;
	
	const response = { message: "User fetched", data: user };

	return res.status(200).json(response);
} );

const refreshAccessToken = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {
		
		console.log("refresh controller");
		console.log("req.body :", req.body);
	}

	const incomingToken = req.cookies.refreshToken;
	if (!incomingToken)  throw new ApiError(401, "Unauthorized");
	
	const decodedToken = jwt.verify(incomingToken, process.env.REFRESH_TOKEN_SECRET);

	const validUser = await User.findById(decodedToken.id);
	
	if (process.env.NODE_ENV === "development") console.log('validUser :', validUser);

	if (!validUser || !validUser.refreshToken) throw new ApiError(401, "Unauthorized");

	if (incomingToken !== validUser.refreshToken) throw new ApiError(401, "Unauthorized");
	const { accessToken, refreshToken } = await generateAccessRefreshToken(validUser._id);

	const validUserJSON = validUser.toJSON();

	const response = { message: "User logged-in successfully", data: validUserJSON, success: true };

	return res.status(200)
	.cookie('accessToken', accessToken, setCookieOptions('accessToken'))
	.cookie('refreshToken', refreshToken, setCookieOptions('refreshToken'))
	.json(response);
} );

export { registerUser, loginUser, logoutUser, getMe, refreshAccessToken }; 