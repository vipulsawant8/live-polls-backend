import asyncHandler from "express-async-handler";
import User from "../models/user.model.js";
import Otp from "../models/otp.model.js";
import ApiError from "../utils/ApiError.js";

import { setCookieOptions, clearCookieOptions } from "../constants/cookieOptions.js";

import crypto from "crypto";

import ERRORS from "../constants/errors.js";

import jwt from 'jsonwebtoken';
import { sendEmail } from "../utils/sendEmail.js";

const OTP_EXIPRY = 10 * 60 * 1000;
const RESEND_COUNTDOWN = 60 * 1000;
const VERIFY_WINDOW = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

const REFRESH_TOKEN_EXPIRY = 14 * 24 * 60 * 60 * 1000;

const OTP_LOCK_WINDOW = 15 * 60 * 1000;

const generateAccessRefreshToken = async ({ userId, deviceId, userAgent, ipAddress }) => {
	const user = await User.findById(userId);
	if (!user) throw new ApiError(404, "User Not Found");

	const accessToken = await user.generateAccessToken(deviceId);
	const refreshToken = await user.generateRefreshToken(deviceId);
	const hashedToken = crypto
		.createHash("sha256")
		.update(refreshToken)
		.digest("hex");

		await User.updateOne(
			{ _id: userId },
			{ $pull: { refreshTokens: { deviceId } } }
		);

		await User.updateOne(
		{ _id: userId },
		{
		$push: {
			refreshTokens: {
			$each: [{
				token: hashedToken,
				deviceId,
				userAgent,
				ipAddress,
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRY)
			}],
			$slice: -5
			}
		}
		}
	);

	const tokens = { accessToken, refreshToken };
	return tokens;
};

const clearAndRespond = function (res) {
  return res.status(200)
    .clearCookie('accessToken', clearCookieOptions('accessToken'))
    .clearCookie('refreshToken', clearCookieOptions('refreshToken'))
    .json({ message: "Logged out successfully.", success: true });
}

const sendOtp = asyncHandler( async (req, res) => {

	const { email } = req.body;

	if (process.env.NODE_ENV === "development") {
		console.log("sendOtp Handler");
		console.log('req.body :', req.body);
	}

	if (!email) throw new ApiError(400, "Email is required");

	const userExists = await User.findOne({ email }).select("-password -refreshTokens");
	if (process.env.NODE_ENV === "development") {
		console.log('userExists :', userExists);
	}

	if (userExists) throw new ApiError(400, "Email already in use please login");

	const existingOtp = await Otp.findOne({ email });
	if (process.env.NODE_ENV === "development") {
		console.log('existingOtp :', existingOtp);
	}
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

	if (process.env.NODE_ENV === "development") {
		console.log("VerifyOtp Handler");
		console.log('req.body :', req.body);
	}

	if (!otp) throw new ApiError(400, "Please enter Otp.");

	const record = await Otp.findOne({ email });
	if (process.env.NODE_ENV === "development") {
		console.log('record :', record);
	}
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
	if (process.env.NODE_ENV === "development") console.log('validUser :', validUser);

	if (!validUser) throw new ApiError(401, ERRORS.INVALID_CREDENTIALS);

	const isPasswordVerified = await validUser.verifyPassword(password);
	if (process.env.NODE_ENV === "development") console.log('isPasswordVerified :', isPasswordVerified);

	if (!isPasswordVerified) throw new ApiError(401, ERRORS.INVALID_CREDENTIALS);

	const { accessToken, refreshToken } = await generateAccessRefreshToken({ userId: validUser._id, deviceId, userAgent: req.get('User-Agent') || '', ipAddress: req.ip });
	
	// const responseUser = validUser.toJSON();

	const response = { message: "Logged in successfully.", data: validUser, success: true };

	return res.status(200)
	.cookie('accessToken', accessToken, setCookieOptions('accessToken'))
	.cookie('refreshToken', refreshToken, setCookieOptions('refreshToken'))
	.json(response);
} );

const logoutUser = asyncHandler( async (req, res) => {

	const incomingToken = req.cookies.refreshToken;

	if (process.env.NODE_ENV === "development") {

		console.log("logotUser controller");
		console.log("req.cookies :", req.cookies);
	}

	if (!incomingToken) {
		return clearAndRespond(res);
	}

	let decodedToken;

	try {
		decodedToken = jwt.verify(
		incomingToken,
		process.env.REFRESH_TOKEN_SECRET
		);
	} catch {
		return clearAndRespond(res);
	}

	const hashedIncomingToken = crypto
		.createHash("sha256")
		.update(incomingToken)
		.digest("hex");

	await User.updateOne(
		{ _id: decodedToken.id },
		{
			$pull: {
				refreshTokens: {
				token: hashedIncomingToken,
				deviceId: decodedToken.deviceId
				}
			}
		}
	);

	return clearAndRespond(res);
} );

const getMe = asyncHandler( async (req, res) => {

	const user = req.user;
	
	const response = { message: "Profile loaded successfully.", data: user };

	return res.status(200).json(response);
} );

const refreshAccessToken = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {
		
		console.log("refresh controller");
		console.log("req.cookies :", req.cookies);
	}
	const incomingToken = req.cookies.refreshToken;
	if (!incomingToken) throw new ApiError(401, "Unauthorized");

	let decodedToken;
	try {
		decodedToken = jwt.verify(
		incomingToken,
		process.env.REFRESH_TOKEN_SECRET
		);
	} catch {
		throw new ApiError(401, "Unauthorized");
	}

	console.log("decodedToken :", decodedToken);

	const hashedIncomingToken = crypto
		.createHash("sha256")
		.update(incomingToken)
		.digest("hex");

	const user = await User.findOne({
		_id: decodedToken.id,
		refreshTokens: {
			$elemMatch: {
			token: hashedIncomingToken,
			deviceId: decodedToken.deviceId,
			expiresAt: { $gt: new Date() }
			}
		}
	});
	console.log("user :", user);

	if (!user) throw new ApiError(401, "Unauthorized");

	const { accessToken, refreshToken } = await generateAccessRefreshToken({ userId: user._id, deviceId: decodedToken.deviceId, userAgent: req.get('User-Agent') || '', ipAddress: req.ip });

	return res.status(200)
		.cookie("accessToken", accessToken, setCookieOptions("accessToken"))
		.cookie("refreshToken", refreshToken, setCookieOptions("refreshToken"))
		.json({
			success: true,
			message: "Session extended successfully"
		});
} );

export { sendOtp, verifyOtp, registerUser, loginUser, logoutUser, getMe, refreshAccessToken }; 