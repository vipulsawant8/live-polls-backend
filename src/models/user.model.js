import { Schema, model } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new Schema({
	
	name: {
		
		type: String,
		required: true,
		trim: true
	},
	email:{
		
		type: String,
		required: true,
		trim: true,
		lowercase: true
	},
	password: {
		
		type: String,
		required: true,
		trim: true
	},
	isVerified: {
		type: Boolean,
		default: false
	},
	refreshTokens : 
		[
			{
				token: {
					type: String,
					required: true,
				},
				deviceId: {
					type: String,
					required: true,
				},
				userAgent: {
					type: String
				},
				ipAddress: {
					type: String
				},
				createdAt: {
					type: Date
				},
				expiresAt: {
					type: Date
				}
			}
		],
	verificationToken: {
		type: String
	},
	verificationTokenExpiry: {
		type: Date
	}
}, { timestamps: true });

userSchema.index({ email: 1 }, { unique:true });
// userSchema.index({ verified: 1 });

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

userSchema.methods.generateAccessToken = function (deviceId) {
	return jwt.sign({ id: this._id, email: this.email , name: this.name, deviceId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
};

userSchema.methods.generateRefreshToken = function (deviceId) {
	return jwt.sign({ id: this._id, deviceId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });
};

const User = model("User", userSchema);

export default User;