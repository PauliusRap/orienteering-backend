# Orienteering Game - Backend API

Go REST API backend for the Orienteering Game scavenger hunt application.

**Live URL**: https://orienteering-game.fly.dev

## Tech Stack

- **Language**: Go 1.24
- **Router**: chi/v5
- **Authentication**: JWT (HS256)
- **Password Hashing**: bcrypt
- **Storage**: In-memory (database integration coming)

## Prerequisites

- Go 1.24 or later

## Local Development

```bash
# Install dependencies
go mod tidy

# Run the server
go run .

# Or use make
make run
```

Server starts on `http://localhost:8080`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `JWT_SECRET` | Secret for JWT signing | `supersecretkey` |
| `ALLOWED_ORIGINS` | CORS origins (comma-separated) | `*` |

## API Endpoints

### Health Check

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | No | Health check |

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | No | Register new user |
| POST | `/api/auth/login` | No | Login, returns JWT token |

### Users

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/users/me` | Yes | Get current user profile |

### Hunts

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/hunts` | No | List all hunts |
| GET | `/api/hunts/{id}` | No | Get hunt details with clues |
| POST | `/api/hunts/{id}/start` | Yes | Start a hunt |

### Progress

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/progress` | Yes | Get player's active hunts |
| GET | `/api/progress/{huntId}` | Yes | Get detailed progress |
| POST | `/api/progress/{huntId}/checkin` | Yes | GPS check-in at location |

### Leaderboards

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/leaderboards/{huntId}` | Yes | Get hunt leaderboard |
| GET | `/api/leaderboards/global` | Yes | Get global leaderboard |

## Example Requests

### Register

```bash
curl -X POST https://orienteering-game.fly.dev/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"player1","email":"player1@example.com","password":"secret123"}'
```

### Login

```bash
curl -X POST https://orienteering-game.fly.dev/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"player1","password":"secret123"}'
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIs..."}
```

### List Hunts

```bash
curl https://orienteering-game.fly.dev/api/hunts
```

### Start a Hunt (authenticated)

```bash
curl -X POST https://orienteering-game.fly.dev/api/hunts/hunt-1/start \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Check-in at Location

```bash
curl -X POST https://orienteering-game.fly.dev/api/progress/hunt-1/checkin \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"latitude":37.7749,"longitude":-122.4194}'
```

## Deployment (Fly.io)

```bash
# Install flyctl
brew install flyctl

# Login
fly auth login

# Deploy
fly deploy

# Set secrets
fly secrets set JWT_SECRET=your-production-secret
fly secrets set ALLOWED_ORIGINS=https://your-app.com
```

## Project Structure

```
backend/
├── main.go         # HTTP handlers and routes
├── storage.go      # In-memory data storage and models
├── go.mod          # Go module definition
├── Dockerfile      # Multi-stage Docker build
├── fly.toml        # Fly.io configuration
├── Makefile        # Build commands
└── openapi.yaml    # API specification
```

## Seed Data

The server starts with demo data:
- **Demo User**: `demo` / `password`
- **Sample Hunts**: "City Sprint" and "Riverside Challenge" with multiple clues

## Future Improvements

- [ ] PostgreSQL database integration
- [ ] Real-time WebSocket updates
- [ ] Hunt creation API
- [ ] Team/multiplayer support
- [ ] Achievement system
