import asyncHandler from "express-async-handler";
import User from "../models/user.model.js";
import Otp from "../models/otp.model.js";
import ApiError from "../utils/ApiError.js";

import { setCookieOptions, clearCookieOptions } from "../constants/cookieOptions.js";

import ERRORS from "../constants/errors.js";

import jwt from 'jsonwebtoken';
import { sendEmail } from "../utils/sendEmail.js";

const OTP_EXIPRY = 10 * 60 * 1000;
const RESEND_COUNTDOWN = 60 * 1000;
const VERIFY_WINDOW = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

const OTP_LOCK_WINDOW = 15 * 60 * 1000;

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

const sendOtp = asyncHandler( async (req, res) => {

	const { email } = req.body;

	if (!email) throw new ApiError(400, "Email is required");

	const userExists = await User.findOne({ email }).select("-password -refreshTokens");
	if (userExists) throw new ApiError(400, "Email already in use please login");

	const existingOtp = await Otp.findOne({ email });
	if (existingOtp) {

		if (existingOtp.lockUntil > Date.now()) {

			const remainingMs = existingOtp.lockUntil - Date.now();
			const remainingMinutes = Math.ceil(remainingMs / 60000);
			throw new ApiError(429, `Wait ${remainingMinutes} minutes before registering.`);
		}
		const timeSinceLastOtp = Date.now() - existingOtp.createdAt;

		if (timeSinceLastOtp < RESEND_COUNTDOWN) {
			
			const waitTime = Math.ceil((RESEND_COUNTDOWN - timeSinceLastOtp)/1000);
			throw new ApiError(429, `Please wait ${waitTime} seconds before requesting another OTP`)
		}
		
		await Otp.deleteMany({ email });
	}

	const otp = Math.floor(100000 + Math.random() * 900000).toString();
	await Otp.create({ email, otp, expiresAt: Date.now() + OTP_EXIPRY });
	
	await sendEmail({ to: email, subject: "OTP verification", text: `Your otp is ${otp}` });

	const response = { success: true, message: "Otp Sent" };
	return res.status(200).json(response);
} );

const verifyOtp = asyncHandler( async (req, res) => {

	const { email, otp } = req.body;
	if (!otp) throw new ApiError(400, "Please enter Otp.");

	const record = await Otp.findOne({ email });
	if (!record) throw new ApiError(400, "OTP not found.");

	if (record.lockUntil && record.lockUntil > new Date()) {

		const remainingMs = record.lockUntil - Date.now();
		const remainingMinutes = Math.ceil(remainingMs / 60000);
		throw new ApiError(429, `Wait ${remainingMinutes} minutes before registering.`);
	}
	
	if (record.expiresAt < Date.now()) throw new ApiError(400, "Otp expired");
	if (record.otp.trim() !== otp.trim()) {
		record.attempts += 1;
		if (record.attempts >= MAX_ATTEMPTS) {
			record.lockUntil = Date.now() + OTP_LOCK_WINDOW;
			await record.save({validateBeforeSave: false});
			throw new ApiError(429, "Too many attempts");
		}
		await record.save({ validateBeforeSave: false });
		throw new ApiError(400, "Invalid Otp");
	}

	record.verified = true;
	record.verifiedAt = new Date();
	// record.attempts = 0;

	await record.save();

	const response = { message: "Otp verified", success: true };
	return res.status(200).json(response);
} );

const registerUser = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {

		console.log("registerUser Handler");
		console.log("req.body :", req.body);
	}

	const email = req.body.email;
	const name = req.body.name;
	const password = req.body.password;

	if (!email || !name || !password) throw new ApiError(400, ERRORS.MISSING_FIELDS);

	const otpRecord = await Otp.findOne({ email });
	if (!otpRecord) throw new ApiError(400, "No verification record found.");

	if (!otpRecord.verified) throw new ApiError(400, "Please verify E-mail first then attempt to register");
	
	const verificationDeadline = otpRecord.verifiedAt.getTime() + VERIFY_WINDOW;
	if (Date.now() > verificationDeadline) {
		await Otp.deleteMany({ email });
		throw new ApiError(400, 'Verification expired. Please verify again.');
	}

	const newUser = await User.create({ email, password, name });
	const userResponse = newUser.toJSON();

	await Otp.deleteMany({ email });

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

	if (!incomingToken || !deviceId)  throw new ApiError(401, "Unauthorized");
	
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

export { sendOtp, verifyOtp, registerUser, loginUser, logoutUser, getMe, refreshAccessToken }; 