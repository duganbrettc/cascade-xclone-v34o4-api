package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var tokenStore = struct {
	sync.RWMutex
	m map[string]int
}{m: make(map[string]int)}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func storeToken(token string, userID int) {
	tokenStore.Lock()
	defer tokenStore.Unlock()
	tokenStore.m[token] = userID
}

func getUserIDFromToken(token string) (int, bool) {
	tokenStore.RLock()
	defer tokenStore.RUnlock()
	id, ok := tokenStore.m[token]
	return id, ok
}

func getBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func requireAuth(r *http.Request) (int, bool) {
	token := getBearerToken(r)
	if token == "" {
		return 0, false
	}
	return getUserIDFromToken(token)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func nullStringVal(ns sql.NullString) interface{} {
	if ns.Valid {
		return ns.String
	}
	return nil
}

// POST /api/auth/signup
func handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if body.Username == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	var userID int
	err = db.QueryRow(
		`INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id`,
		body.Username, string(hash),
	).Scan(&userID)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			writeError(w, http.StatusConflict, "username already taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	token := generateToken()
	storeToken(token, userID)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"user_id":       userID,
		"session_token": token,
	})
}

// POST /api/auth/login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	var userID int
	var hash string
	err := db.QueryRow(
		`SELECT id, password_hash FROM users WHERE username = $1`,
		body.Username,
	).Scan(&userID, &hash)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token := generateToken()
	storeToken(token, userID)
	writeJSON(w, http.StatusOK, map[string]string{"session_token": token})
}

// GET /api/users/me
// PATCH /api/users/me
func handleMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireAuth(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method == http.MethodGet {
		var u struct {
			ID          int
			Username    string
			DisplayName sql.NullString
			Bio         sql.NullString
		}
		err := db.QueryRow(
			`SELECT id, username, display_name, bio FROM users WHERE id = $1`, userID,
		).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Bio)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"user_id":      u.ID,
			"username":     u.Username,
			"display_name": nullStringVal(u.DisplayName),
			"bio":          nullStringVal(u.Bio),
		})
		return
	}
	if r.Method == http.MethodPatch {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		setClauses := []string{}
		args := []interface{}{}
		argIdx := 1

		if val, ok := body["display_name"]; ok {
			setClauses = append(setClauses, fmt.Sprintf("display_name = $%d", argIdx))
			args = append(args, val)
			argIdx++
		}
		if val, ok := body["bio"]; ok {
			setClauses = append(setClauses, fmt.Sprintf("bio = $%d", argIdx))
			args = append(args, val)
			argIdx++
		}
		if val, ok := body["password"]; ok {
			if pw, ok := val.(string); ok && pw != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "failed to hash password")
					return
				}
				setClauses = append(setClauses, fmt.Sprintf("password_hash = $%d", argIdx))
				args = append(args, string(hash))
				argIdx++
			}
		}
		if len(setClauses) > 0 {
			args = append(args, userID)
			query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setClauses, ", "), argIdx)
			if _, err := db.Exec(query, args...); err != nil {
				writeError(w, http.StatusInternalServerError, "db error")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// GET /api/users/{username}
func handleUserByUsername(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/users/")
	username := strings.TrimSuffix(path, "/")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}
	var u struct {
		ID          int
		Username    string
		DisplayName sql.NullString
		Bio         sql.NullString
	}
	err := db.QueryRow(
		`SELECT id, username, display_name, bio FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Bio)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":      u.ID,
		"username":     u.Username,
		"display_name": nullStringVal(u.DisplayName),
		"bio":          nullStringVal(u.Bio),
	})
}

// GET /api/users
func handleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rows, err := db.Query(`SELECT id, username, display_name FROM users ORDER BY username`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()
	type UserEntry struct {
		UserID      int         `json:"user_id"`
		Username    string      `json:"username"`
		DisplayName interface{} `json:"display_name"`
	}
	users := []UserEntry{}
	for rows.Next() {
		var u UserEntry
		var dn sql.NullString
		if err := rows.Scan(&u.UserID, &u.Username, &dn); err != nil {
			continue
		}
		u.DisplayName = nullStringVal(dn)
		users = append(users, u)
	}
	writeJSON(w, http.StatusOK, users)
}

// POST /api/posts
func handleCreatePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID, ok := requireAuth(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if body.Body == "" {
		writeError(w, http.StatusBadRequest, "body required")
		return
	}
	var postID int
	var createdAt time.Time
	err := db.QueryRow(
		`INSERT INTO posts (user_id, body) VALUES ($1, $2) RETURNING id, created_at`,
		userID, body.Body,
	).Scan(&postID, &createdAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         postID,
		"user_id":    userID,
		"body":       body.Body,
		"created_at": createdAt,
	})
}

// GET /api/posts/by/{username}
func handlePostsByUsername(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/posts/by/")
	username := strings.TrimSuffix(path, "/")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}
	rows, err := db.Query(`
		SELECT p.id, p.user_id, p.body, p.created_at, u.username
		FROM posts p
		JOIN users u ON p.user_id = u.id
		WHERE u.username = $1
		ORDER BY p.created_at DESC
		LIMIT 50
	`, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()
	posts := []map[string]interface{}{}
	for rows.Next() {
		var id, userID int
		var body string
		var createdAt time.Time
		var uname string
		if err := rows.Scan(&id, &userID, &body, &createdAt, &uname); err != nil {
			continue
		}
		posts = append(posts, map[string]interface{}{
			"id":         id,
			"user_id":    userID,
			"body":       body,
			"created_at": createdAt,
			"username":   uname,
		})
	}
	writeJSON(w, http.StatusOK, posts)
}

// POST /api/follow/{username}
// DELETE /api/follow/{username}
func handleFollow(w http.ResponseWriter, r *http.Request) {
	followerID, ok := requireAuth(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/follow/")
	username := strings.TrimSuffix(path, "/")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}
	if r.Method == http.MethodPost {
		var followeeID int
		err := db.QueryRow(`SELECT id FROM users WHERE username = $1`, username).Scan(&followeeID)
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		_, err = db.Exec(`
			INSERT INTO follows (follower_id, followee_id) VALUES ($1, $2) ON CONFLICT DO NOTHING
		`, followerID, followeeID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]int{
			"follower_id": followerID,
			"followee_id": followeeID,
		})
		return
	}
	if r.Method == http.MethodDelete {
		var followeeID int
		err := db.QueryRow(`SELECT id FROM users WHERE username = $1`, username).Scan(&followeeID)
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		_, err = db.Exec(`DELETE FROM follows WHERE follower_id = $1 AND followee_id = $2`, followerID, followeeID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// GET /api/follow/status?username=X
func handleFollowStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	followerID, ok := requireAuth(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}
	var followeeID int
	err := db.QueryRow(`SELECT id FROM users WHERE username = $1`, username).Scan(&followeeID)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM follows WHERE follower_id = $1 AND followee_id = $2`, followerID, followeeID).Scan(&count)
	writeJSON(w, http.StatusOK, map[string]bool{"following": count > 0})
}

// GET /api/timeline
func handleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID, ok := requireAuth(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rows, err := db.Query(`
		SELECT p.id, p.user_id, p.body, p.created_at, u.username
		FROM posts p
		JOIN users u ON p.user_id = u.id
		WHERE p.user_id = $1 OR p.user_id IN (SELECT followee_id FROM follows WHERE follower_id = $1)
		ORDER BY p.created_at DESC
		LIMIT 50
	`, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()
	posts := []map[string]interface{}{}
	for rows.Next() {
		var id, uid int
		var body, username string
		var createdAt time.Time
		if err := rows.Scan(&id, &uid, &body, &createdAt, &username); err != nil {
			continue
		}
		posts = append(posts, map[string]interface{}{
			"id":         id,
			"user_id":    uid,
			"body":       body,
			"created_at": createdAt,
			"username":   username,
		})
	}
	writeJSON(w, http.StatusOK, posts)
}

var dbReady = make(chan struct{})

func withDB(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-dbReady:
			h(w, r)
		case <-timer.C:
			writeError(w, http.StatusServiceUnavailable, "database not ready")
		case <-r.Context().Done():
			writeError(w, http.StatusServiceUnavailable, "service starting up")
		}
	}
}

func connectDB(dbURL string) {
	var err error
	for i := 1; ; i++ {
		var d *sql.DB
		d, err = sql.Open("postgres", dbURL)
		if err == nil {
			if err = d.Ping(); err == nil {
				db = d
				log.Println("connected to db")
				close(dbReady)
				return
			}
			d.Close()
		}
		log.Printf("waiting for db... (attempt %d): %v", i, err)
		time.Sleep(2 * time.Second)
	}
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://xclone:xclone@localhost:5432/xclone?sslmode=disable"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	go connectDB(dbURL)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/api/auth/signup", withDB(handleSignup))
	mux.HandleFunc("/api/auth/login", withDB(handleLogin))
	mux.HandleFunc("/api/users/me", withDB(handleMe))
	mux.HandleFunc("/api/posts", withDB(handleCreatePost))
	mux.HandleFunc("/api/timeline", withDB(handleTimeline))
	mux.HandleFunc("/api/follow/status", withDB(handleFollowStatus))

	// More specific prefixes registered before broader ones
	mux.HandleFunc("/api/posts/by/", withDB(handlePostsByUsername))
	mux.HandleFunc("/api/follow/", withDB(handleFollow))
	mux.HandleFunc("/api/users/", withDB(handleUserByUsername))
	mux.HandleFunc("/api/users", withDB(handleListUsers))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to bind :%s: %v", port, err)
	}
	log.Printf("xclone-api listening on :%s", port)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
