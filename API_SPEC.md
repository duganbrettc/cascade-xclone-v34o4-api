# xclone-v34o4 API Specification

Base URL: `http://api:8080` (compose-internal); proxied via web at `/api/*`

All authenticated endpoints require `Authorization: Bearer <session_token>`.

---

## Health

### GET /healthz
Returns service liveness.

**Response 200**
```
ok
```

---

## Auth

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
Authenticate and obtain a session token.

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

## Users

### GET /api/users/me
Return the authenticated user's profile.

**Auth required**

**Response 200**
```json
{ "user_id": 1, "username": "alice", "display_name": "Alice", "bio": "Hello world" }
```

**Response 401** – missing or invalid token

---

### PATCH /api/users/me
Update the authenticated user's profile fields.

**Auth required**

**Request body** (all fields optional)
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

## Posts

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

## Follow / Unfollow

### POST /api/follow/{username}
Follow a user. Idempotent — a second call returns 201 (not 409).

**Auth required**

**Response 201**
```json
{ "follower_id": 1, "followee_id": 2 }
```

**Response 404** – target user not found

---

### DELETE /api/follow/{username}
Unfollow a user. Idempotent — 204 even if not following.

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

---

## Timeline

### GET /api/timeline
Return the authenticated user's timeline: posts from users they follow, newest first, capped at 50.

**Auth required**

**Response 200**
```json
[
  { "id": 42, "user_id": 2, "body": "bob-said-hello", "created_at": "2026-05-31T12:00:00Z", "username": "bob" }
]
```
