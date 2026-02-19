package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"
    "math"
    "sort"
    "os"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    jwt "github.com/golang-jwt/jwt/v4"
    "golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

func init() {
    sec := os.Getenv("JWT_SECRET")
    if sec == "" {
        sec = "supersecretkey"
    }
    jwtSecret = []byte(sec)
}

// Simple CORS middleware for mobile apps
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origins := os.Getenv("ALLOWED_ORIGINS")
        origin := r.Header.Get("Origin")
        allow := false
        if origins == "" || origins == "*" {
            allow = true
        } else {
            for _, o := range strings.Split(origins, ",") {
                if strings.TrimSpace(o) == origin {
                    allow = true
                    break
                }
            }
        }
        if allow && origin != "" {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Vary", "Origin")
            w.Header().Set("Access-Control-Allow-Credentials", "true")
            w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        }
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        next.ServeHTTP(w, r)
    })
}

 

func main() {
    // Seed data (users, hunts, clues)
    seedData()

    router := setupRouter()
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Starting server on :%s...", port)
    if err := http.ListenAndServe(":"+port, router); err != nil {
        log.Fatalf("server failed: %v", err)
    }
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Simple JSON responder helpers
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    if payload != nil {
        _ = json.NewEncoder(w).Encode(payload)
    }
}

func respondError(w http.ResponseWriter, status int, message string) {
    respondJSON(w, status, map[string]string{"error": message})
}

// Context key for current user
type contextKey string
const userCtxKey = contextKey("user")

// Helper to fetch user from context
func currentUser(r *http.Request) *User {
    if v := r.Context().Value(userCtxKey); v != nil {
        if u, ok := v.(*User); ok {
            return u
        }
    }
    return nil
}

// Build router with routes and handlers wired up
func setupRouter() *chi.Mux {
    r := chi.NewRouter()
    // CORS middleware handles origins for mobile clients
    r.Use(corsMiddleware)
    r.Use(middleware.Recoverer)
    r.Use(middleware.RequestID)
    r.Use(middleware.Logger)

    // Health endpoint for liveness checks
    r.Get("/health", handleHealth)

    // Public auth and hunts endpoints
    r.Route("/api", func(api chi.Router) {
        api.Post("/auth/register", handleRegister)
        api.Post("/auth/login", handleLogin)
        api.Get("/hunts", handleListHunts)
        api.Get("/hunts/{id}", handleGetHunt)

        // Protected endpoints
        api.With(authMiddleware).Get("/users/me", handleMe)

        api.With(authMiddleware).Post("/hunts/{id}/start", handleStartHunt)

        api.With(authMiddleware).Get("/progress", handleListProgress)
        api.With(authMiddleware).Get("/progress/{huntId}", handleProgressDetail)
        api.With(authMiddleware).Post("/progress/{huntId}/checkin", handleCheckIn)

        api.With(authMiddleware).Get("/leaderboards/{huntId}", handleLeaderboard)
        api.With(authMiddleware).Get("/leaderboards/global", handleGlobalLeaderboard)
    })

    return r
}

// --- Handlers ---

func handleRegister(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username string `json:"username"`
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    if req.Username == "" || req.Email == "" || req.Password == "" {
        respondError(w, http.StatusBadRequest, "missing fields")
        return
    }
    // Check existing user
    for _, u := range users {
        if u.Username == req.Username || u.Email == req.Email {
            respondError(w, http.StatusBadRequest, "user exists")
            return
        }
    }
    hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    u := &User{ID: newID(), Username: req.Username, Email: req.Email, PasswordHash: string(hash), CreatedAt: time.Now()}
    users[u.ID] = u
    respondJSON(w, http.StatusCreated, map[string]interface{}{
        "id":        u.ID,
        "username":  u.Username,
        "email":     u.Email,
        "createdAt": u.CreatedAt,
    })
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    // Find user by username or email
    var found *User
    for _, u := range users {
        if u.Username == req.Username || u.Email == req.Username {
            found = u
            break
        }
    }
    if found == nil {
        respondError(w, http.StatusUnauthorized, "invalid credentials")
        return
    }
    if err := bcrypt.CompareHashAndPassword([]byte(found.PasswordHash), []byte(req.Password)); err != nil {
        respondError(w, http.StatusUnauthorized, "invalid credentials")
        return
    }
    // Create JWT
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub":      found.ID,
        "username": found.Username,
        "exp":      time.Now().Add(24 * time.Hour).Unix(),
    })
    tokenString, _ := token.SignedString(jwtSecret)
    respondJSON(w, http.StatusOK, map[string]string{"token": tokenString})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    if user == nil {
        respondError(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    respondJSON(w, http.StatusOK, map[string]interface{}{
        "id":        user.ID,
        "username":  user.Username,
        "email":     user.Email,
        "createdAt": user.CreatedAt,
    })
}

func handleListHunts(w http.ResponseWriter, r *http.Request) {
    out := make([]*Hunt, 0, len(hunts))
    for _, h := range hunts {
        out = append(out, h)
    }
    respondJSON(w, http.StatusOK, out)
}

func handleGetHunt(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    h, ok := hunts[id]
    if !ok {
        respondError(w, http.StatusNotFound, "hunt not found")
        return
    }
    respondJSON(w, http.StatusOK, h)
}

func handleStartHunt(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    if user == nil { respondError(w, http.StatusUnauthorized, "unauthorized"); return }
    huntID := chi.URLParam(r, "id")
    h, ok := hunts[huntID]
    if !ok { respondError(w, http.StatusNotFound, "hunt not found"); return }
    key := fmt.Sprintf("%s|%s", user.ID, huntID)
    if p, exists := progresses[key]; exists {
        respondJSON(w, http.StatusOK, p)
        return
    }
    p := &Progress{ID: newID(), UserID: user.ID, HuntID: huntID, CurrentClueIndex: 0, StartedAt: time.Now()}
    progresses[key] = p
    _ = h
    respondJSON(w, http.StatusCreated, p)
}

func handleListProgress(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    if user == nil { respondError(w, http.StatusUnauthorized, "unauthorized"); return }
    list := []*Progress{}
    for _, p := range progresses {
        if p.UserID == user.ID {
            list = append(list, p)
        }
    }
    respondJSON(w, http.StatusOK, list)
}

func handleProgressDetail(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    if user == nil { respondError(w, http.StatusUnauthorized, "unauthorized"); return }
    huntID := chi.URLParam(r, "huntId")
    key := fmt.Sprintf("%s|%s", user.ID, huntID)
    p, ok := progresses[key]
    if !ok {
        respondError(w, http.StatusNotFound, "progress not found")
        return
    }
    respondJSON(w, http.StatusOK, p)
}

type checkInReq struct {
    Latitude  float64 `json:"latitude"`
    Longitude float64 `json:"longitude"`
}

func handleCheckIn(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    if user == nil { respondError(w, http.StatusUnauthorized, "unauthorized"); return }
    huntID := chi.URLParam(r, "huntId")
    key := fmt.Sprintf("%s|%s", user.ID, huntID)
    p, ok := progresses[key]
    if !ok {
        respondError(w, http.StatusNotFound, "progress not found; start the hunt first")
        return
    }
    var req checkInReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondError(w, http.StatusBadRequest, "invalid body")
        return
    }
    h := hunts[huntID]
    if h == nil || len(h.Clues) == 0 {
        respondError(w, http.StatusBadRequest, "hunt has no clues")
        return
    }
    if p.CurrentClueIndex >= len(h.Clues) {
        respondError(w, http.StatusBadRequest, "hunt already completed")
        return
    }
    clue := h.Clues[p.CurrentClueIndex]
    dist := haversine(req.Latitude, req.Longitude, clue.Latitude, clue.Longitude)
    if dist > clue.Radius {
        respondError(w, http.StatusBadRequest, "not within clue radius")
        return
    }
    // accepted check-in
    c := &CheckIn{ID: newID(), ProgressID: p.ID, ClueID: clue.ID, Timestamp: time.Now(), Latitude: req.Latitude, Longitude: req.Longitude}
    checkIns = append(checkIns, c)
    p.CurrentClueIndex++
    p.CheckedCount++
    // Completion check
    if p.CurrentClueIndex >= len(h.Clues) {
        t := time.Now()
        p.CompletedAt = &t
    }
    respondJSON(w, http.StatusOK, p)
}

func handleLeaderboard(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    _ = user
    huntID := chi.URLParam(r, "huntId")
    h, ok := hunts[huntID]
    if !ok {
        respondError(w, http.StatusNotFound, "hunt not found")
        return
    }
    // score per user: completedClues or total clues if completed
    type entry struct {
        UserID   string `json:"userId"`
        Username string `json:"username"`
        Score    int    `json:"score"`
        Completed bool  `json:"completed"`
    }
    m := []entry{}
    for _, p := range progresses {
        if p.HuntID != huntID { continue }
        uname := users[p.UserID].Username
        sc := p.CheckedCount
        completed := false
        if p.CompletedAt != nil {
            sc = len(h.Clues)
            completed = true
        }
        m = append(m, entry{UserID: p.UserID, Username: uname, Score: sc, Completed: completed})
    }
    // sort by score desc
    sort.Slice(m, func(i, j int) bool {
        if m[i].Score == m[j].Score {
            return m[i].Username < m[j].Username
        }
        return m[i].Score > m[j].Score
    })
    respondJSON(w, http.StatusOK, map[string]interface{}{
        "hunt":   h.Name,
        "leadership": m,
    })
}

func handleGlobalLeaderboard(w http.ResponseWriter, r *http.Request) {
    // aggregate scores per user across hunts (completed hunts count + clues solved)
    type entry struct{ UserID, Username string; Score int }
    m := []entry{}
    // compute per user by iterating progresses
    scores := map[string]int{}
    for _, p := range progresses {
        if p.CompletedAt != nil {
            // full completion yields a base score of 100 for visibility, but we compute per user total completed hunts
            scores[p.UserID] += 1
        } else {
            scores[p.UserID] += p.CheckedCount
        }
    }
    for uid, sc := range scores {
        uname := users[uid].Username
        m = append(m, entry{UserID: uid, Username: uname, Score: sc})
    }
    sort.Slice(m, func(i, j int) bool {
        if m[i].Score == m[j].Score {
            return m[i].Username < m[j].Username
        }
        return m[i].Score > m[j].Score
    })
    respondJSON(w, http.StatusOK, map[string]interface{}{
        "globalLeaders": m,
    })
}

// --- Helpers ---

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        if auth == "" {
            respondError(w, http.StatusUnauthorized, "missing authorization header")
            return
        }
        parts := strings.SplitN(auth, " ", 2)
        if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
            respondError(w, http.StatusUnauthorized, "invalid authorization header")
            return
        }
        tokenStr := parts[1]
        token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
            return jwtSecret, nil
        })
        if err != nil || !token.Valid {
            respondError(w, http.StatusUnauthorized, "invalid token")
            return
        }
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            respondError(w, http.StatusUnauthorized, "invalid token claims")
            return
        }
        uid, _ := claims["sub"].(string)
        if uid == "" {
            respondError(w, http.StatusUnauthorized, "invalid token subject")
            return
        }
        user := users[uid]
        if user == nil {
            respondError(w, http.StatusUnauthorized, "user not found")
            return
        }
        ctx := context.WithValue(r.Context(), userCtxKey, user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// --- Utilities ---

func newID() string {
    return fmt.Sprintf("id_%d", time.Now().UnixNano())
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
    // returns distance in meters
    const R = 6371000 // Earth radius in meters
    toRad := func(a float64) float64 { return a * (3.141592653589793 / 180) }
    dLat := toRad(lat2 - lat1)
    dLon := toRad(lon2 - lon1)
    a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(toRad(lat1))*math.Cos(toRad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
    c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
    return R * c
}
