import e, { json, urlencoded, static as static_ } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';

import morgan from 'morgan';

import authRoutes from "./routes/auth.routes.js";
import pollRoutes from "./routes/poll.routes.js";

import errorHandler from './middlewares/error/errorHandler.middleware.js';

const app = e();

app.disable('x-powered-by');
app.set('trust proxy', true);

const allowedOrigins = process.env.CORS_ORIGIN.split(',');
if (process.env.NODE_ENV !== "production") console.log("Allowed CORS Origins :", allowedOrigins);

const corsOptions = {
	origin: function (origin, callback) {
		// allow requests with no origin 
		// (like mobile apps or curl requests)
		if (!origin) return callback(null, true);
		if (allowedOrigins.indexOf(origin) === -1) {
			const msg = `The CORS policy for this site does not allow access from the specified Origin.`;
			return callback(new Error(msg), false);
		}
		return callback(null, true);
	},
	methods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
	credentials: true
};

const urlOptions = {
	limit: "50mb",
	extended: true
};

const jsonOptions = {
	limit: "50mb"
};

app.use(cors(corsOptions));

app.use(json(jsonOptions));
app.use(urlencoded(urlOptions));
app.use(static_("public"));

app.use(cookieParser());

const morganFormat = process.env.NODE_ENV === "production" ? "combined" : "dev";
app.use(morgan(morganFormat));

const apiRoute = '/api/v1';

app.use(`${apiRoute}/auth`, authRoutes);
app.use(`${apiRoute}/polls`, pollRoutes);

app.use((req, res) => {
	res.status(404).json({ message: "Route not found", success: false });
});

app.use(errorHandler);

export default app;