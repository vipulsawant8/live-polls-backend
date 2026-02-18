import { POLL_EVENTS } from "../events/pollEvents.js";
import { joinPollHandler, castVoteHandler, addPollHandler, closePollHandler, leavePollHandler } from "../handlers/pollHandlers.js";

const pollReceiver = (io, socket) => {

	socket.on(POLL_EVENTS.JOIN_POLL, (data) => {
		joinPollHandler(io, socket, data);
	});

	socket.on(POLL_EVENTS.CAST_VOTE, (data) => {
		castVoteHandler(io, socket, data);
	});

	socket.on(POLL_EVENTS.ADD_POLL, (data) => {
		addPollHandler(io, socket, data);
	});

	socket.on(POLL_EVENTS.CLOSE_POLL, (data) => {
		closePollHandler(io, socket, data);
	});

	socket.on(POLL_EVENTS.LEAVE_POLL, (data) => {
		leavePollHandler(io, socket, data);
	});
};

export default pollReceiver;