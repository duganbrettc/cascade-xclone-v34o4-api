# cascade-xclone-v34o4-api

Go HTTP service for the xclone v34o4 platform. Uses `database/sql` + `lib/pq` + `golang.org/x/crypto/bcrypt`. Reads `PORT` (default `8080`) and `DATABASE_URL` from environment. Auth via random 32-byte hex Bearer tokens in an in-memory map.

## Running

```sh
DATABASE_URL=postgres://user:pass@host:5432/dbname?sslmode=disable PORT=8080 ./api
```

## Docker

```sh
docker build -t xclone-api .
docker run -e DATABASE_URL=... -e PORT=8080 -p 8080:8080 xclone-api
```

---

## xclone-v34o4-api-spec

Base URL: `http://api:8080` (compose-internal); proxied via nginx at `/api/*` and `/healthz`.

All authenticated endpoints require the header:
```
Authorization: Bearer <session_token>
```

---

### GET /healthz

Liveness probe. No auth required.

**Response 200**
```
ok
```

---

### POST /api/auth/signup

Create a new user account.

**Request body**
```json
{ "username": "alice", "password": "secret" }
```

**Response 201**
```json
{ "user_id": 1, "session_token": "<64-hex-char token>" }
```

**Response 409** – username already taken
```json
{ "error": "username already taken" }
```

---

### POST /api/auth/login

Authenticate and get a session token.

**Request body**
```json
{ "username": "alice", "password": "secret" }
```

**Response 200**
```json
{ "session_token": "<64-hex-char token>" }
```

**Response 401** – wrong credentials
```json
{ "error": "invalid credentials" }
```

---

### GET /api/users/me

Return the authenticated user's profile.

**Auth required**

**Response 200**
```json
{ "user_id": 1, "username": "alice", "display_name": "Alice", "bio": "Hello" }
```

**Response 401** – missing or invalid token

---

### PATCH /api/users/me

Update the authenticated user's profile fields. All fields are optional.

**Auth required**

**Request body**
```json
{ "display_name": "Alice Updated", "bio": "New bio", "password": "newpass" }
```

**Response 200**
```json
{ "ok": true }
```

---

### GET /api/users/{username}

Return a public profile for the given username.

**Response 200**
```json
{ "user_id": 1, "username": "alice", "display_name": "Alice", "bio": "Hello" }
```

**Response 404** – user not found

---

### GET /api/users

List all users.

**Response 200**
```json
[
  { "user_id": 1, "username": "alice", "display_name": "Alice" },
  { "user_id": 2, "username": "bob",   "display_name": null }
]
```

---

### POST /api/posts

Create a new post.

**Auth required**

**Request body**
```json
{ "body": "Hello world!" }
```

**Response 201**
```json
{ "id": 42, "user_id": 1, "body": "Hello world!", "created_at": "2026-05-31T12:00:00Z" }
```

**Response 401** – missing or invalid token

---

### GET /api/posts/by/{username}

List the most recent 50 posts by the given user, newest first.

**Response 200**
```json
[
  { "id": 42, "user_id": 1, "body": "Hello world!", "created_at": "2026-05-31T12:00:00Z", "username": "alice" }
]
```

---

### POST /api/follow/{username}

Follow a user. **Idempotent** — a second call returns `201` (not `409`).

**Auth required**

**Response 201**
```json
{ "follower_id": 1, "followee_id": 2 }
```

**Response 404** – target user not found

---

### DELETE /api/follow/{username}

Unfollow a user. **Idempotent** — `204` even if not currently following.

**Auth required**

**Response 204** (no body)

---

### GET /api/follow/status?username={username}

Check whether the authenticated user follows `username`.

**Auth required**

**Response 200**
```json
{ "following": true }
```

**Response 404** – target user not found

---

### GET /api/timeline

Return the authenticated user's timeline: posts from users they follow, newest first, capped at 50.

**Auth required**

**Response 200**
```json
[
  { "id": 42, "user_id": 2, "body": "bob-said-hello", "created_at": "2026-05-31T12:00:00Z", "username": "bob" }
]
```

**Response 401** – missing or invalid token
