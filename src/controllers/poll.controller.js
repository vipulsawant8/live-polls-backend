import asyncHandler from 'express-async-handler';
import Poll from '../models/poll.model.js';

import ApiError from '../utils/ApiError.js';
import ERRORS from '../constants/errors.js';

import { randomUUID } from "crypto";

const createPoll = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {
		
		console.log("createPoll controller");
		console.log("req.body :", req.body);
	}

	const userID = req.user._id;

	const { title, options } = req.body;

	if (!title || !options || !Array.isArray(options) || options.length < 2)  throw new ApiError(400, ERRORS.POLL_DATA_REQUIRED);

	const formatedOpts = options.map(text => ({ text, vote: 0, optionID: randomUUID() }));

	const poll = await Poll.create({ userID, options: formatedOpts, title });

	const response = { success: true, data: poll, message: "Poll created successfully" };
	return res.status(201).json(response);
} );

const fetchPolls = asyncHandler( async (req, res) => {

	const polls = await Poll.find().sort({ createdAt: -1 }).lean();
	const response = { success: true, data: polls, message: "Polls fetched successfully" };
	return res.status(200).json(response);
} );

const getPollByID = asyncHandler( async (req, res) => {

	if (process.env.NODE_ENV === "development") {
		
		console.log("getPollByID controller");
		console.log("req.params :", req.params);
	}
	
	const pollID = req.params.id;

	const poll = await Poll.findById(pollID);
	if (!poll) throw new ApiError(404, ERRORS.POLL_NOT_FOUND);

	const response = { success: true, data: poll, message: "Poll fetched successfully" };
	return res.status(200).json(response);
} );

const closePoll = asyncHandler( async (req, res) => {
	if (process.env.NODE_ENV === "development") {
		
		console.log("closePoll controller");
		console.log("req.params :", req.params);
	}

	const userID = req.user._id;
	const pollID = req.params.id;

	const poll = await Poll.findById(pollID);
	if (!poll) throw new ApiError(404, ERRORS.POLL_NOT_FOUND);

	if (!poll.userID.equals(userID)) throw new ApiError(403, ERRORS.POLL_CLOSE_ACTION_FORBIDDEN);

	if (!poll.open) throw new ApiError(400, ERRORS.POLL_CLOSED);
	poll.open = false;
	await poll.save();
	
	const response = { success: true, data: poll, message: "Poll closed successfully" };
	return res.status(200).json(response);
} );

export { createPoll, fetchPolls, getPollByID, closePoll };