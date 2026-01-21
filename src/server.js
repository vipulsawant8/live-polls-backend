import './loadEnv.js';

import http from "http";
import { Server } from 'socket.io';

import app from './app.js';
import connectDB from './db/connectDB.js';

import socketHandler from './socket/service.js';

const initiateServer = async () => {
	
	try {
		
		console.log("Server Initiated");
		
		const server = http.createServer(app);
		const io = new Server(server, {
			cors:{
				origin: process.env.CORS_ORIGIN,
				credentials: true
			}
		});

		socketHandler(io);

		await connectDB();

		const PORT = process.env.PORT;
		server.listen(PORT, () => {

			console.log(`Server running successfully on port ${PORT}`);
		});
	} catch (error) {
		
		console.error(error.message);
		console.log("Error :", error);
		process.exit(1);
	}
};

initiateServer();