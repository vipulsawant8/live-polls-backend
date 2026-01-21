# Live Polls — Backend API (Node.js + Express + Socket.IO)

![License](https://img.shields.io/github/license/vipulsawant8/notes-app-backend)
![Node](https://img.shields.io/badge/node-%3E%3D18.x-brightgreen)
![Express](https://img.shields.io/badge/express-5.x-black)
![MongoDB](https://img.shields.io/badge/mongodb-database-green)
![Socket.IO](https://img.shields.io/badge/socket.io-realtime-black)
![Render](https://img.shields.io/badge/render-deployed-success?logo=render&logoColor=white)

Backend API for a Polling / Voting application, built with Node.js, Express, MongoDB, and Socket.IO.

This service handles authentication, poll management, vote persistence, and real-time vote updates, using a cookie-based session model with access and refresh token rotation.

## Architecture Overview

The backend follows a modular Express architecture with real-time capabilities layered on top using Socket.IO:

- REST APIs → authentication, polls, votes
- Socket.IO services → real-time vote broadcasting
- Routing → endpoint definitions
- Controllers → request handling and response shaping
- Middleware → authentication and centralized error handling
- Models → data schemas and business rules
- Utilities → shared helpers and abstractions

All endpoints are versioned under `/api/v1`.  
All security-sensitive logic (tokens, cookies, session validation) is handled exclusively on the server.

## Error Message Management

Application error messages are centralized in a shared constants file.

- All reusable error messages are defined in `constants/errors.js`
- Controllers reference predefined error keys instead of hardcoded strings
- This ensures consistent API responses across authentication, polls, and voting logic
- Improves maintainability and reduces duplication in controller logic

## Authentication & Session Strategy

This backend implements **cookie-based authentication with refresh token rotation**.

### Key characteristics

- Access and refresh tokens are issued by the server
- Tokens are stored in HTTP-only cookies
- Tokens are never exposed to frontend JavaScript
- Refresh tokens are **persisted in the database**
- Refresh tokens are **rotated on every successful refresh**
- Sessions are tracked per device using a client-generated `deviceId`

### Session Lifecycle

1.  User logs in with credentials
2. Server issues:
	- Short-lived access token
	- Long-lived refresh token
3. Both tokens are set as HTTP-only cookies
4. Protected routes validate the access token
5. When access token expires:
	- Client calls /auth/refresh-token
	- Server validates and rotates refresh token
	- New cookies are issued
6. On logout:
	- Refresh token is removed from the database
	- Cookies are cleared

If refresh validation fails, **the session is invalidated** and the user must re-authenticate.

## API Design Principles

- REST APIs for data mutation and validation
- WebSockets for real-time state propagation
- Stateless access tokens
- Refresh token rotation to prevent replay attacks
- Centralized error handling
- No token storage on the client
- Minimal surface area for authentication logic

## Project Structure

```bash
src
├── app.js
├── constants
│   ├── errors.js
│   └── setCookieOptions.js
├── controllers
│   ├── auth.controller.js
│   └── poll.controller.js
├── db
│   └── connectDB.js
├── loadEnv.js
├── middlewares
│   ├── auth
│   │   └── verifyLogin.js
│   └── error
│       └── errorHandler.middleware.js
├── models
│   ├── poll.model.js
│   ├── vote.model.js
│   └── user.model.js
├── routes
│   ├── auth.routes.js
│   └── poll.routes.js
├── socket
│   ├── events
│   │   └── pollEvents.js
│   ├── handlers
│   │   └── pollHandlers.js
│   ├── receivers
│   │   └── pollReceiver.js
│   └── service.js
├── server.js
└── utils
    └── ApiError.js
```

## Folder responsibilities

- controllers/ – business logic and response formatting
- routes/ – endpoint definitions and middleware wiring
- middlewares/ – authentication guards and error handling
- models/ – MongoDB schemas and data rules
- socket/ – real-time event handling and broadcasting
- constants/ – shared configuration (cookie options)
- utils/ – reusable helpers and abstractions

## Authentication Middleware

Protected routes use a dedicated authentication middleware:

- Reads access token from HTTP-only cookies
- Verifies token signature and expiration
- Fetches user from database
- Attaches user to req.user

Refresh logic is intentionally not handled in middleware and remains centralized in the refresh endpoint.

## Real-Time Voting with Socket.IO

This backend supports real-time vote updates using Socket.IO.
- Socket.IO is used only for broadcasting vote updates. All validation and data persistence is handled via REST APIs.
- Votes are persisted using REST APIs
- Vote updates are broadcast to connected clients via WebSockets
- Socket logic is isolated from REST controllers

Socket design

- events/ – defines poll-related socket events
- handlers/ – server-side event handling logic
- receivers/ – incoming socket event listeners
- service.js – Socket.IO server initialization

This separation keeps REST APIs stateless while enabling live UI updates.

## Live Polls API Behavior

- Polls are user-scoped
- User can:
	1. Create polls
	2. vote on polls
- Votes are:
	1. Persisted in MongoDB
	2. Broadcast in real-time to connected clients
- Server ensures:
	1. Valid voting rules
	2. Data integrity
	3. Authorization checks

All validation and authorization checks are enforced by the backend.

## Error Handling

All errors are handled by a single centralized error handler.

Handled cases include:

- MongoDB duplicate key errors
- Mongoose validation errors
- Invalid ObjectId errors
- JWT verification errors
- Malformed JSON payloads
- Custom ApiError instances

Error responses are sanitized in production to avoid leaking internal details.

## Environment Configuration

Only an example file is committed:

```bash
.env.example
```

Required environment variables include:

- PORT
- NODE_ENV
- MONGO_URI
- ACCESS_TOKEN_SECRET
- REFRESH_TOKEN_SECRET
- CORS_ORIGIN
- ACCESS_TOKEN_EXPIRY
- REFRESH_TOKEN_EXPIRY

All secrets are managed server-side.  
JWT expiration is configured via environment variables, while cookie lifetimes are defined in code to ensure consistent browser behavior.

## Frontend Integration

This backend is consumed by a separately deployed frontend.

- Frontend Repository: https://github.com/vipulsawant8/live-polls-frontend
- Frontend Stack: React, Redux Toolkit, Axios, Socket.IO client
- Auth Integration:  Cookie-based authentication with refresh token rotation
- Real-Time Updates: Socket.IO

The frontend does not manage tokens and relies entirely on server-side session handling.

## Security Considerations

- Tokens stored only in HTTP-only cookies
- Refresh tokens rotated on every use
- Logout invalidates refresh token in database
- No sensitive data returned in API responses
- Error messages sanitized in production

This backend is intended for portfolio and demo usage, not high-risk production systems.

## Getting Started (Local Development)

1. Clone the repository
2. Install dependencies
```bash
npm install
```
3. Create an environment file
```bash
cp .env.example .env.development
```
4. Start the server
```bash
npm run dev
```
The API will be available at:
```bash
http://localhost:<PORT>/api/v1
```

## License

This project is licensed under the MIT License.