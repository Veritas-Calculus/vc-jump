// CLI management commands for vc-jump.
// Usage:
//
//	vc-jump user create --username admin --role admin
//	vc-jump user list
//	vc-jump host list
//	vc-jump host import hosts.json
//	vc-jump apikey create --name terraform --user admin
//	vc-jump migrate status
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Veritas-Calculus/vc-jump/internal/auth"
	"github.com/Veritas-Calculus/vc-jump/internal/config"
	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// handleCLI processes CLI subcommands. Returns true if a CLI command was handled.
func handleCLI(args []string, configPath string) bool {
	if len(args) < 1 {
		return false
	}

	// Check if this is a CLI command (not a flag).
	cmd := args[0]
	switch cmd {
	case "user", "host", "apikey", "migrate":
		// CLI command — proceed.
	default:
		return false
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	store, err := storage.NewSQLiteStore(cfg.Storage)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	switch cmd {
	case "user":
		handleUserCLI(ctx, args[1:], store)
	case "host":
		handleHostCLI(ctx, args[1:], store)
	case "apikey":
		handleAPIKeyCLI(ctx, args[1:], store)
	case "migrate":
		handleMigrateCLI(store)
	}
	return true
}

func handleUserCLI(ctx context.Context, args []string, store *storage.SQLiteStore) {
	if len(args) == 0 {
		fmt.Println("Usage: vc-jump user <command>")
		fmt.Println("Commands: list, create, delete")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		users, err := store.ListUsers(ctx)
		if err != nil {
			log.Fatalf("failed to list users: %v", err)
		}
		fmt.Printf("%-36s  %-20s  %-8s  %-10s  %-20s\n", "ID", "USERNAME", "ACTIVE", "SOURCE", "GROUPS")
		fmt.Println("------------------------------------  --------------------  --------  ----------  --------------------")
		for _, u := range users {
			groups := "[]"
			if len(u.Groups) > 0 {
				g, _ := json.Marshal(u.Groups)
				groups = string(g)
			}
			active := "yes"
			if !u.IsActive {
				active = "no"
			}
			fmt.Printf("%-36s  %-20s  %-8s  %-10s  %-20s\n", u.ID, u.Username, active, u.Source, groups)
		}
		fmt.Printf("\nTotal: %d users\n", len(users))

	case "create":
		if len(args) < 3 {
			fmt.Println("Usage: vc-jump user create <username> <password> [--role <role>]")
			os.Exit(1)
		}
		username, password := args[1], args[2]

		hash, err := auth.HashPassword(password)
		if err != nil {
			log.Fatalf("failed to hash password: %v", err)
		}

		user := &storage.UserWithPassword{
			User: storage.User{
				Username: username,
				Source:   storage.UserSourceLocal,
				Groups:   []string{},
				IsActive: true,
			},
			PasswordHash: hash,
			IsActive:     true,
		}

		if err := store.CreateUserWithPassword(ctx, user); err != nil {
			log.Fatalf("failed to create user: %v", err)
		}

		// Assign role if specified.
		for i, a := range args {
			if a == "--role" && i+1 < len(args) {
				roleName := args[i+1]
				role, err := store.GetRoleByName(ctx, roleName)
				if err != nil {
					log.Fatalf("role '%s' not found: %v", roleName, err)
				}
				if err := store.AssignRole(ctx, user.ID, role.ID); err != nil {
					log.Fatalf("failed to assign role: %v", err)
				}
				fmt.Printf("Assigned role: %s\n", roleName)
			}
		}

		fmt.Printf("Created user: %s (ID: %s)\n", username, user.ID)

	case "delete":
		if len(args) < 2 {
			fmt.Println("Usage: vc-jump user delete <username>")
			os.Exit(1)
		}
		username := args[1]
		user, err := store.GetUserByUsername(ctx, username)
		if err != nil {
			log.Fatalf("user '%s' not found", username)
		}
		if err := store.DeleteUser(ctx, user.ID); err != nil {
			log.Fatalf("failed to delete user: %v", err)
		}
		fmt.Printf("Deleted user: %s\n", username)

	default:
		fmt.Printf("Unknown user command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleHostCLI(ctx context.Context, args []string, store *storage.SQLiteStore) {
	if len(args) == 0 {
		fmt.Println("Usage: vc-jump host <command>")
		fmt.Println("Commands: list, import")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		hosts, err := store.ListHosts(ctx)
		if err != nil {
			log.Fatalf("failed to list hosts: %v", err)
		}
		fmt.Printf("%-36s  %-20s  %-20s  %-6s  %-10s\n", "ID", "NAME", "ADDR", "PORT", "USER")
		fmt.Println("------------------------------------  --------------------  --------------------  ------  ----------")
		for _, h := range hosts {
			fmt.Printf("%-36s  %-20s  %-20s  %-6d  %-10s\n", h.ID, h.Name, h.Addr, h.Port, h.User)
		}
		fmt.Printf("\nTotal: %d hosts\n", len(hosts))

	case "import":
		if len(args) < 2 {
			fmt.Println("Usage: vc-jump host import <file.json>")
			os.Exit(1)
		}

		data, err := os.ReadFile(args[1])
		if err != nil {
			log.Fatalf("failed to read file: %v", err)
		}

		var hosts []struct {
			Name string `json:"name"`
			Addr string `json:"addr"`
			Port int    `json:"port"`
			User string `json:"user"`
		}
		if err := json.Unmarshal(data, &hosts); err != nil {
			log.Fatalf("failed to parse JSON: %v", err)
		}

		created, skipped := 0, 0
		for _, h := range hosts {
			if h.Port == 0 {
				h.Port = 22
			}
			if h.User == "" {
				h.User = "root"
			}

			existing, _ := store.GetHostByName(ctx, h.Name)
			if existing != nil {
				skipped++
				continue
			}

			host := &storage.Host{
				Name: h.Name,
				Addr: h.Addr,
				Port: h.Port,
				User: h.User,
			}
			if err := store.CreateHost(ctx, host); err != nil {
				fmt.Printf("  ✗ %s: %v\n", h.Name, err)
			} else {
				fmt.Printf("  ✓ %s\n", h.Name)
				created++
			}
		}
		fmt.Printf("\nImported: %d created, %d skipped\n", created, skipped)

	default:
		fmt.Printf("Unknown host command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleAPIKeyCLI(ctx context.Context, args []string, store *storage.SQLiteStore) {
	if len(args) == 0 {
		fmt.Println("Usage: vc-jump apikey <command>")
		fmt.Println("Commands: list, create")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		users, err := store.ListUsers(ctx)
		if err != nil {
			log.Fatalf("failed to list users: %v", err)
		}
		fmt.Printf("%-36s  %-20s  %-36s  %-8s  %-20s\n", "ID", "NAME", "USER_ID", "ACTIVE", "PREFIX")
		fmt.Println("------------------------------------  --------------------  ------------------------------------  --------  --------------------")
		total := 0
		for _, u := range users {
			keys, err := store.ListApiKeysByUser(ctx, u.ID)
			if err != nil {
				continue
			}
			for _, k := range keys {
				active := "yes"
				if !k.IsActive {
					active = "no"
				}
				fmt.Printf("%-36s  %-20s  %-36s  %-8s  %-20s\n", k.ID, k.Name, k.UserID, active, k.TokenPrefix)
				total++
			}
		}
		fmt.Printf("\nTotal: %d API keys\n", total)

	case "create":
		if len(args) < 3 {
			fmt.Println("Usage: vc-jump apikey create <name> --user <username>")
			os.Exit(1)
		}

		name := args[1]
		var username string
		for i, a := range args {
			if a == "--user" && i+1 < len(args) {
				username = args[i+1]
			}
		}
		if username == "" {
			fmt.Println("--user is required")
			os.Exit(1)
		}

		user, err := store.GetUserByUsername(ctx, username)
		if err != nil {
			log.Fatalf("user '%s' not found: %v", username, err)
		}

		token, err := auth.GenerateToken()
		if err != nil {
			log.Fatalf("failed to generate token: %v", err)
		}

		prefix := "vcj_" + token[:8]
		tokenHash := auth.HashToken(token)

		apiKey := &storage.ApiKey{
			UserID:      user.ID,
			Name:        name,
			TokenPrefix: prefix,
			TokenHash:   tokenHash,
			Scopes:      []string{"*"},
			IsActive:    true,
		}

		if err := store.CreateApiKey(ctx, apiKey); err != nil {
			log.Fatalf("failed to create API key: %v", err)
		}

		fmt.Printf("Created API key: %s\n", name)
		fmt.Printf("  ID:    %s\n", apiKey.ID)
		fmt.Printf("  Token: vcj_%s\n", token)
		fmt.Println("\n⚠ Save this token now — it cannot be shown again!")

	default:
		fmt.Printf("Unknown apikey command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleMigrateCLI(store *storage.SQLiteStore) {
	version, err := store.GetMigrationVersion()
	if err != nil {
		log.Fatalf("failed to get migration version: %v", err)
	}
	fmt.Printf("Current schema migration version: %d\n", version)
}
