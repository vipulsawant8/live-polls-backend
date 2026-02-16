import jwt from "jsonwebtoken";

import pollReceiver from "./receivers/pollReceiver.js";
import { parseCookie } from "cookie";

const socketHandler = (io) => {

	io.use((socket, next) => {

		const cookieHeader =  socket.handshake.headers.cookie || "";
		if (process.env.NODE_ENV !== "production") console.log("cookieHeader :", cookieHeader);

		const cookies = parseCookie(cookieHeader);
		const accessToken = cookies.accessToken;
		
		if (process.env.NODE_ENV !== "production") console.log("accessToken :", accessToken);

		// const accessToken = socket.handshake.auth?.token;
		if (!accessToken) {
			socket.userID = null;
			return next();
		}

		try {
			
			const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
			if (process.env.NODE_ENV !== "production") console.log("decoded :", decoded);
			socket.userID = decoded.id;
		} catch (error) {
			
			socket.userID = null;
			if (process.env.NODE_ENV !== "production") console.log("error :", error);
		}

		next();
	});

	io.on('connection', (socket) => {
		console.log("Connected:", socket.id);
		pollReceiver(io, socket);
	});
};

export default socketHandler;