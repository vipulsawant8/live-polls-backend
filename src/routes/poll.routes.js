import { Router } from "express";

import verifyLogin from "../middlewares/auth/verifyLogin.js";

import { validate } from "../middlewares/validate/validate.middleware.js";
import { addPollSchema } from "../validations/poll.schema.js";
import { objectIdParamSchema } from "../validations/auth.schema.js";
import { closePoll, createPoll, fetchPolls/*, getPollByID*/ } from "../controllers/poll.controller.js";

const router = Router();

router.use(verifyLogin);

router.get('/', fetchPolls);
// router.get('/:id', getPollByID);

router.post('/', validate({ body: addPollSchema }), createPoll);
router.post('/:id/close', validate({ params: objectIdParamSchema }), closePoll);

export default router;