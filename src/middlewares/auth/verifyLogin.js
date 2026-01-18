import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import ApiError from "../../utils/ApiError.js";
import User from "../../models/user.model.js";

const verifyLogin = asyncHandler( async (req, res, next) => {
	
	const accessToken = req.cookies?.accessToken;

	if (!accessToken) throw new ApiError(401, "Unauthorized");

	let decodedToken;
	try {
		
		decodedToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
	} catch (error) {
		
		throw new ApiError(401, "Unauthorized")
	}

	if (!decodedToken.id) throw new ApiError(401, "Unauthorized");

	const user = await User.findById(decodedToken.id).select("-password -refreshToken");

	if (!user) throw new ApiError(404, "User not found");

	req.user = user;
	next();
} );

export default verifyLogin;