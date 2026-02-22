import ApiError from "../../utils/ApiError.js";

export const validate = (schemas) => (req, res, next) => {
	try {
		if (schemas.body) {
			req.body = schemas.body.parse(req.body);
		}

		if (schemas.params) {
			req.params = schemas.params.parse(req.params);
		}

		if (schemas.query) {
			req.query = schemas.query.parse(req.query);
		}

		next();
	} catch (error) {
		const message =
			error?.issues?.[0]?.message || "Validation error";

		next(new ApiError(400, message));
	}
};