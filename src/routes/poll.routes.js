import { Router } from "express";

import verifyLogin from "../middlewares/auth/verifyLogin.js";
import { closePoll, createPoll, fetchPolls/*, getPollByID*/ } from "../controllers/poll.controller.js";

const router = Router();

router.use(verifyLogin);

router.get('/', fetchPolls);
// router.get('/:id', getPollByID);

router.post('/', createPoll);
router.post('/:id/close', closePoll);

export default router;