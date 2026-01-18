import { Router } from "express";

import { getMe, loginUser, logoutUser, registerUser, refreshAccessToken } from "../controllers/auth.controller.js";
import verifyLogin from "../middlewares/auth/verifyLogin.js";

const router = Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/logout', verifyLogin, logoutUser);

router.get('/me', verifyLogin, getMe);
router.post('/refresh-token', refreshAccessToken);

export default router;