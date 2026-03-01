# GEMINI.md - VC Jump Project Context

## Project Overview
**VC Jump** is a lightweight SSH bastion host (jump server) written in Go. It is designed to be a single-binary deployment with a built-in Web Dashboard for managing hosts, users, and SSH sessions.

### Key Technologies
- **Language:** Go 1.24+
- **SSH Protocol:** `golang.org/x/crypto/ssh`
- **Database:** SQLite (pure Go implementation via `modernc.org/sqlite`)
- **Web UI:** REST API with a static HTML/JS dashboard
- **Real-time Monitoring:** WebSockets for live session watching
- **Storage:** Local file system or S3 (for session recordings)
- **Auth:** TOTP (Two-Factor Authentication) and RBAC (Role-Based Access Control)

### Architecture
The project follows a modular structure within the `internal/` directory:
- `server`: The main SSH server entry point that handles incoming connections.
- `proxy`: Manages the connection and data forwarding to target hosts.
- `dashboard`: Implements the management API and serves the static Web UI.
- `storage`: Handles data persistence using SQLite.
- `recording`: Records SSH sessions to local storage or S3.
- `rbac`: Implements fine-grained access control.
- `audit`: Logs all administrative and connection events.
- `selector`: An interactive terminal UI for users to choose target hosts.

## Building and Running

### Development Commands
Use the provided `Makefile` for common tasks:
- **Build:** `make build` (creates the `vc-jump` binary)
- **Run:** `make run`
- **Test:** `make test` (runs all tests with race detection)
- **Lint:** `make lint` (requires `golangci-lint`)
- **Format:** `make fmt`
- **Clean:** `make clean`

### Docker
- **Build Image:** `make docker-build`
- **Run Container:** `docker run -p 2222:2222 -p 8080:8080 -v ./data:/app/data vc-jump -config /app/config.yaml`

## Development Conventions

### Coding Style
- Follow standard Go idioms and `gofmt`.
- Use `internal/` for private packages to prevent external imports.
- Dependency injection is preferred (e.g., passing `Config`, `Logger`, and `Store` to constructors).

### Error Handling
- Use the standard `errors` package.
- Wrap errors with context using `fmt.Errorf("context: %w", err)`.

### Testing
- Unit tests are located alongside the source code (e.g., `*_test.go`).
- Integration tests are found in `internal/integration/`.
- Use `make test` to ensure all tests pass before submitting changes.

### Security
- Never hardcode secrets. Use `config.yaml` or environment variables.
- Sensitive data in the database (like passwords) must be hashed.
- SSH private keys for target hosts should be handled securely through the `sshkey` package.

## Key Files
- `cmd/vc-jump/main.go`: The main entry point.
- `internal/server/server.go`: Core SSH server logic.
- `internal/proxy/proxy.go`: SSH proxy and session handling.
- `config.example.yaml`: Reference for all configuration options.
- `go.mod`: Project dependencies.
