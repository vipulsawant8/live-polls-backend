import Poll from "../../models/poll.model.js";
import Vote from "../../models/vote.model.js";

import { Document } from "mongoose";

const joinPollHandler = async(io, socket, { pollID }) => {

	const room = `poll:${pollID}`;
	socket.join(room);

	try {
		const poll = await Poll.findById(pollID).lean();
	
		if (poll) {
			
			io.to(room).emit('poll-data', { poll });
		}
	} catch (error) {
		
		if (process.env.NODE_ENV !== "production") console.log("error :", error);
	}
};

const castVoteHandler = async(io, socket, { pollID, optionID, optionDocID }) => {

	if (process.env.NODE_ENV !== "production") console.log("castVoteHandler :", pollID, optionID, optionDocID);

	const userID = socket.userID;

	if (process.env.NODE_ENV !== "production") console.log(userID);

	const room = `poll:${pollID}`;

	if (!userID) {
		
		return socket.emit('vote-rejected', { message: "Login required" });
	}

	const poll = await Poll.findById(pollID);

	if (!poll) {
		
		return socket.emit('vote-rejected', { message: "Poll not found" });
	}

	if (!poll.open) {
		return socket.emit('vote-rejected', { message: "Poll is closed" });
	}

	const duplicate = await Vote.findOne({ userID, pollID }).lean();
	
	if (duplicate) {
		return socket.emit('vote-rejected', { message: "Vote already casted" });
	}
	if (process.env.NODE_ENV !== "production") console.log("is document:", poll instanceof Document);
	if (process.env.NODE_ENV !== "production") console.log("options constructor:", poll.options.constructor.name);

	const option = poll.options.id(optionDocID);

	if (!option) {
		return socket.emit('vote-rejected', { message: "Option not found" });
	}

	await Vote.create({
		pollID,
		userID,
		optionID
	});

	option.votes += 1;
	await poll.save();

	const updated = await Poll.findById(pollID).lean();
	io.to(room).emit('poll-data', { poll: updated });

	socket.emit('vote-accepted', { message: "Vote counted" });
};

export { castVoteHandler, joinPollHandler };