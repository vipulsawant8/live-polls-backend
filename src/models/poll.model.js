import { Schema, Types, model } from "mongoose";

const optionsSchema = new Schema({
	optionID: {
		type: String,
		required: true
	},
	text: {
		type: String,
		required: true
	},
	votes: {
		type: Number,
		default: 0
	}
}, { _id: true });

const pollSchema = new Schema({
	
	userID: {
		
		type: Types.ObjectId,
		ref: "User",
		required: true
	},
	title:{
		
		type: String,
		required: true,
		trim: true
	},
	options: {
		type: [optionsSchema],
		validate: v => v.length >= 2
	},
	open: {
		type: Boolean,
		default: true
	},
	expiresAt: {
		type: Date,
		required: true
	}
}, { timestamps: true });

pollSchema.index({ userID: 1, title: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });

pollSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

pollSchema.methods.toJSON = function () {

	const poll = this.toObject();
	delete poll.__v;
	return poll;
};
const Poll = model('Poll', pollSchema);

export default Poll;