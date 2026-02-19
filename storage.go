package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
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
    IsAdmin      bool      `json:"isAdmin"`
}

// Hunt and related models
type Hunt struct {
    ID          string  `json:"id"`
    Name        string  `json:"name"`
    Description string  `json:"description"`
    Difficulty  string  `json:"difficulty"`
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
    // Seed an admin user if there are no users yet
    adminPw, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
    admin := &User{ID: nextID(), Username: "admin", Email: "admin@example.com", PasswordHash: string(adminPw), CreatedAt: time.Now(), IsAdmin: true}
    users[admin.ID] = admin
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

// Persistence helpers
type dataStore struct {
    Users      map[string]*User   `json:"users"`
    Hunts      map[string]*Hunt   `json:"hunts"`
    Progresses map[string]*Progress `json:"progresses"`
    CheckIns   []*CheckIn         `json:"checkIns"`
    IDCounter  int64              `json:"idCounter"`
}

func dataFilePath() string {
    if p := os.Getenv("DATA_FILE"); p != "" {
        return p
    }
    return "./data.json"
}

func SaveData() error {
    ds := dataStore{
        Users:      users,
        Hunts:      hunts,
        Progresses: progresses,
        CheckIns:   checkIns,
        IDCounter:  idCounter,
    }
    b, err := json.MarshalIndent(ds, "", "  ")
    if err != nil {
        return err
    }
    return ioutil.WriteFile(dataFilePath(), b, 0644)
}

func LoadData() error {
    path := dataFilePath()
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return nil
    }
    b, err := ioutil.ReadFile(path)
    if err != nil {
        return err
    }
    ds := dataStore{}
    if err := json.Unmarshal(b, &ds); err != nil {
        return err
    }
    if ds.Users != nil { users = ds.Users }
    if ds.Hunts != nil { hunts = ds.Hunts }
    if ds.Progresses != nil { progresses = ds.Progresses }
    if ds.CheckIns != nil { checkIns = ds.CheckIns }
    idCounter = ds.IDCounter
    return nil
}
