import { connect } from "mongoose";
import User from "../models/user.model.js";
import Poll from "../models/poll.model.js";
import Vote from "../models/vote.model.js";

const connectDB = async () => {

	try {

		const DB_PATH = process.env.DB_CONNECT_STRING;

		if (!DB_PATH) {
			throw new Error("DB_CONNECT_STRING is not defined in environment variables");
		}

		const conn = await connect(DB_PATH);

		if (process.env.NODE_ENV !== "production") {
			console.log("MongoDB connection name :", conn.connection.name);
			console.log("MongoDB connection collections :", Object.keys(conn.connection.collections));
		}

		await Vote.syncIndexes();
		await Poll.syncIndexes();
		await User.syncIndexes();
	} catch (error) {
		
		console.log("Mongo Connection Error :", error);
		process.exit(1);
	}
};

export default connectDB;