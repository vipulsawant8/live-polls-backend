import { Schema, model } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new Schema({
	
	name: {
		
		type: String,
		require: true,
		trim: true
	},
	email:{
		
		type: String,
		require: true,
		trim: true,
		lowercase: true
	},
	password: {
		
		type: String,
		require: true,
		trim: true
	},
	refreshTokens : 
		[
			{
				token: {
					type: String,
					require: true,
				},
				deviceId: {
					type: String,
					require: true,
				},
				userAgent: {
					type: String
				},
				ipAddress: {
					type: String
				},
				createdAt: {
					type: Date,
					default: Date.now,
				}
			}
		]
}, { timestamps: true });

userSchema.index({ email: 1 }, { unique:true })

userSchema.pre('save', async function () {

	if (this.isModified('password')) {

		this.password = await bcrypt.hash(this.password, 10);
	}; 
});

userSchema.methods.toJSON = function () {

	const user = this.toObject();
	delete user.refreshTokens;
	delete user.password;
	return user;
};

userSchema.methods.verifyPassword = async function (password) {

	return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {

	return jwt.sign({ id: this._id, email: this.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
};

userSchema.methods.generateRefreshToken = function () {

	return jwt.sign({ id: this._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });
};

const User = model("User", userSchema);

export default User;