package main

import (
    "fmt"
    "time"
    "sync/atomic"

    "golang.org/x/crypto/bcrypt"
)

// In-memory data stores (reset on restart). Prepared for future DB integration.
var (
    users       = map[string]*User{}
    hunts       = map[string]*Hunt{}
    progresses  = map[string]*Progress{} // key: userID|huntID
    checkIns    = []*CheckIn{}
    idCounter   int64 = 0
    onceSeeded  uint32
)

func nextID() string {
    return fmt.Sprintf("id_%d", atomic.AddInt64(&idCounter, 1))
}

// User model
type User struct {
    ID           string    `json:"id"`
    Username     string    `json:"username"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"`
    CreatedAt    time.Time `json:"createdAt"`
}

// Hunt and related models
type Hunt struct {
    ID          string  `json:"id"`
    Name        string  `json:"name"`
    Description string  `json:"description"`
    Clues       []Clue  `json:"clues"`
    CreatedAt   time.Time `json:"createdAt"`
}

type Clue struct {
    ID        string  `json:"id"`
    HuntID    string  `json:"huntId"`
    Order     int     `json:"order"`
    Hint      string  `json:"hint"`
    Latitude  float64 `json:"latitude"`
    Longitude float64 `json:"longitude"`
    Radius    float64 `json:"radius"`
}

type Progress struct {
    ID                 string     `json:"id"`
    UserID             string     `json:"userId"`
    HuntID             string     `json:"huntId"`
    CurrentClueIndex   int        `json:"currentClueIndex"`
    StartedAt          time.Time  `json:"startedAt"`
    CompletedAt        *time.Time `json:"completedAt"`
    CheckedCount       int        `json:"checkedCount"`
}

type CheckIn struct {
    ID          string    `json:"id"`
    ProgressID  string    `json:"progressId"`
    ClueID      string    `json:"clueId"`
    Timestamp   time.Time `json:"timestamp"`
    Latitude    float64   `json:"latitude"`
    Longitude   float64   `json:"longitude"`
}

// Helper to seed initial data if not present
func seedInitialData() {
    if len(users) > 0 {
        return
    }
    // Seed a demo user and two hunts with clues
    // Password: password
    pwHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
    user := &User{ID: nextID(), Username: "demo", Email: "demo@example.com", PasswordHash: string(pwHash), CreatedAt: time.Now()}
    users[user.ID] = user

    // Hunt 1
    h1 := &Hunt{ID: nextID(), Name: "City Sprint", Description: "Navigate city clues to finish", CreatedAt: time.Now()}
    h1.Clues = []Clue{
        {ID: nextID(), HuntID: h1.ID, Order: 1, Hint: "Start near the old clock tower.", Latitude: 37.7739, Longitude: -122.4313, Radius: 60},
        {ID: nextID(), HuntID: h1.ID, Order: 2, Hint: "Look for a mural beside the river.", Latitude: 37.7710, Longitude: -122.4230, Radius: 50},
        {ID: nextID(), HuntID: h1.ID, Order: 3, Hint: "Finish at the hilltop fountain.", Latitude: 37.7695, Longitude: -122.4160, Radius: 60},
    }
    hunts[h1.ID] = h1

    // Hunt 2
    h2 := &Hunt{ID: nextID(), Name: "Riverside Challenge", Description: "Clues along the waterfront", CreatedAt: time.Now()}
    h2.Clues = []Clue{
        {ID: nextID(), HuntID: h2.ID, Order: 1, Hint: "Where ducks gather, look up.", Latitude: 37.8000, Longitude: -122.4100, Radius: 70},
        {ID: nextID(), HuntID: h2.ID, Order: 2, Hint: "Under the bridge you will find the next hint.", Latitude: 37.7980, Longitude: -122.4120, Radius: 60},
    }
    hunts[h2.ID] = h2
}

func seedData() {
    seedInitialData()
}
