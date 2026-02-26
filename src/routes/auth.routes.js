import { Router } from "express";

import { createdUserLimiter, verifyEmailLimiter, loginLimiter, changePasswordLimiter, forgotPasswordLimiter, refreshTokenLimiter, resetPasswordLimiter  } from "../middlewares/limiters/setLimiters.js";
import { validate } from "../middlewares/validate/validate.middleware.js";
import { createAccountSchema, verifyEmailSchema, loginUserSchema, changePasswordSchema, forgotPasswordSchema, resetPasswordSchema } from "../validations/auth.schema.js";
import { getMe, loginUser, logoutUser, createAccount, verifyEmail, refreshAccessToken, changePassword, forgotPassword, resetPassword } from "../controllers/auth.controller.js";
import verifyLogin from "../middlewares/auth/verifyLogin.js";

const router = Router();

router.post('/create-account', createdUserLimiter, validate({ body: createAccountSchema }), createAccount);
router.post('/verify-email', verifyEmailLimiter, validate({ body: verifyEmailSchema }), verifyEmail);

router.post('/login', loginLimiter, validate({ body: loginUserSchema }), loginUser);
router.post('/logout', logoutUser);

router.get('/me', verifyLogin, getMe);
router.post('/refresh-token', refreshTokenLimiter,  refreshAccessToken);

router.post('/change-password', changePasswordLimiter, verifyLogin, validate({ body: changePasswordSchema }), changePassword);
router.post('/forgot-password', forgotPasswordLimiter, validate({ body: forgotPasswordSchema }), forgotPassword);
router.post('/reset-password', resetPasswordLimiter, validate({ body: resetPasswordSchema }), resetPassword);

export default router;