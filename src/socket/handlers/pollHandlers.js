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
	try{
	const userID = socket.userID;
    const room = `poll:${pollID}`;

    if (!userID) {
      return socket.emit("vote-rejected", { message: "Login required" });
    }

    // 1️⃣ Ensure poll exists and is open
    const poll = await Poll.findOne({ _id: pollID, open: true }).lean();
    if (!poll) {
      return socket.emit("vote-rejected", { message: "Poll not found or closed" });
    }

    // 2️⃣ Create vote (DB-level duplicate protection)
    await Vote.create({ pollID, userID, optionID });

    // 3️⃣ Atomic increment of selected option
    const updateResult = await Poll.updateOne(
      { _id: pollID, open: true, "options._id": optionDocID },
      { $inc: { "options.$.votes": 1 } }
    );

    if (updateResult.modifiedCount === 0) {
      return socket.emit("vote-rejected", { message: "Option not found" });
    }

    // 4️⃣ Fetch updated poll
    const updatedPoll = await Poll.findById(pollID).lean();

    // 5️⃣ Broadcast to room
    io.to(room).emit("poll-data", { poll: updatedPoll });

    socket.emit("vote-accepted", { message: "Vote counted" });

  } catch (err) {
    if (err.code === 11000) {
      return socket.emit("vote-rejected", { message: "Vote already casted" });
    }

    console.error("Vote error:", err);
    socket.emit("vote-rejected", { message: "Internal server error" });
  }
};

export { castVoteHandler, joinPollHandler };