import { Router } from "express";

import { createdUserLimiter, verifyEmailLimiter, loginLimiter, changePasswordLimiter, forgotPasswordLimiter, refreshTokenLimiter  } from "../middlewares/limiters/setLimiters.js";
import { validate } from "../middlewares/validate/validate.middleware.js";
import { createAccountSchema, verifyEmailSchema, loginUserSchema } from "../validations/auth.schema.js";
import { getMe, loginUser, logoutUser, createAccount, verifyEmail, refreshAccessToken } from "../controllers/auth.controller.js";
import verifyLogin from "../middlewares/auth/verifyLogin.js";

const router = Router();

router.post('/create-account', createdUserLimiter, validate({ body: createAccountSchema }), createAccount);
router.post('/verify-email', verifyEmailLimiter, validate({ body: verifyEmailSchema }), verifyEmail);

router.post('/login', loginLimiter, validate({ body: loginUserSchema }), loginUser);
router.post('/logout', logoutUser);

router.get('/me', verifyLogin, getMe);
router.post('/refresh-token', refreshTokenLimiter,  refreshAccessToken);

export default router;