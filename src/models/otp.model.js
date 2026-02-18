import { Schema, model } from "mongoose";

const otpSchema = new Schema({
    
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true
    },
    otp: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    verified: {
        type: Boolean,
        required: false,
        default: false
    },
    verifiedAt: {
        type: Date,
        required: false,
        default: null
    },
    attempts: {
        type: Number,
        required: false,
        default: 0
    },
    lockUntil: {
        type: Date
    }
    // used: {
    //     type: Boolean,
    //     default: false
    // }
}, {
    timestamps: true
});

const Otp = model("Otp", otpSchema);

export default Otp;