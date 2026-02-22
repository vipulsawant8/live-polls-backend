import z from "zod";
import { Types } from "mongoose";

/* -------------------------------------------------- */
/* Helpers */
/* -------------------------------------------------- */

export const objectIdParamSchema = z.object({
	id: z.string().refine(
		(val) => Types.ObjectId.isValid(val),
		{ message: "Invalid ID" }
	)
});

/* -------------------------------------------------- */
/* Register */
/* -------------------------------------------------- */

export const createAccountSchema = z.object({
	name: z.string().trim().min(1, "Name is required"),
	email: z.email("Invalid email"),
	password: z.string().min(6, "Password must be at least 6 characters")
});

/* -------------------------------------------------- */
/* Verify Email */
/* -------------------------------------------------- */

export const verifyEmailSchema = z.object({
	token: z.string().trim().min(1, "Token is required")
});

/* -------------------------------------------------- */
/* Login */
/* -------------------------------------------------- */

export const loginUserSchema = z.object({
	identity: z.string().trim().min(1, "Identity is required"),
	password: z.string().trim().min(1, "Password is required"),
	deviceId: z.uuid("Invalid deviceId")
});

/* -------------------------------------------------- */
/* Change Password (Authenticated) */
/* -------------------------------------------------- */

export const changePasswordSchema = z.object({
	currentPassword: z.string().min(1, "Current password is required"),
	newPassword: z.string().min(6, "New password must be at least 6 characters")
});

/* -------------------------------------------------- */
/* Forgot Password */
/* -------------------------------------------------- */

export const forgotPasswordSchema = z.object({
	email: z.email("Invalid email")
});

/* -------------------------------------------------- */
/* Reset Password */
/* -------------------------------------------------- */

export const resetPasswordSchema = z.object({
	token: z.string().trim().min(1, "Reset token is required"),
	newPassword: z.string().min(6, "Password must be at least 6 characters")
});