import { Schema, model, Types } from "mongoose";

 const voteSchema = new Schema({
	
	userID: {
		
		type: Types.ObjectId,
		ref: "User",
		require: true
	},
	pollID: {
		
		type: Types.ObjectId,
		ref: "Poll",
		require: true
	},
	optionID:  {
		
		type: String,
		require: true
	},
	expiresAt: {
		type: Date,
		required: true
	}
}, { timestamps: true });

voteSchema.index({ userID: 1, pollID: 1 }, { unique: true });
voteSchema.index(
	{ expiresAt: 1 },
	{ expireAfterSeconds: 0 }
);

const Vote = model("Vote", voteSchema);

export default Vote;