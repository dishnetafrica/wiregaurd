// Package store is the SQLite persistence layer. Every mutation that must be
// atomic (activation, revocation, allocation) happens inside Tx.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrNotFound = errors.New("store: not found")

type DB struct {
	sql *sql.DB
}

// Open opens (and creates) the database at path and applies migrations.
// Use ":memory:" only in tests.
func Open(path string) (*DB, error) {
	dsn := path
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite with WAL is safe for one process; serialise writers to avoid
	// SQLITE_BUSY under concurrent activations.
	db.SetMaxOpenConns(1)
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: %s: %w", p, err)
		}
	}
	s := &DB{sql: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (d *DB) Close() error { return d.sql.Close() }

func (d *DB) migrate() error {
	if _, err := d.sql.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		var n int
		if err := d.sql.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name=?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := d.sql.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)`, name, Now()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Now returns the canonical timestamp representation used in every table.
func Now() string { return time.Now().UTC().Format(time.RFC3339) }

// ParseTime parses a timestamp written by Now. Empty/NULL gives the zero time.
func ParseTime(s sql.NullString) time.Time {
	if !s.Valid || s.String == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s.String)
	return t
}

func nullTime(t time.Time) sql.NullString {
	if t.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: t.UTC().Format(time.RFC3339), Valid: true}
}

// Tx runs fn inside a transaction, committing on nil error.
func (d *DB) Tx(ctx context.Context, fn func(tx *Tx) error) error {
	raw, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	tx := &Tx{tx: raw, ctx: ctx}
	if err := fn(tx); err != nil {
		raw.Rollback()
		return err
	}
	return raw.Commit()
}

// Tx is an open transaction. All query helpers hang off it so that callers
// cannot accidentally mix transactional and non-transactional access.
type Tx struct {
	tx  *sql.Tx
	ctx context.Context
}

// View runs fn in a read-only transaction (same snapshot for all reads).
func (d *DB) View(ctx context.Context, fn func(tx *Tx) error) error {
	raw, err := d.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer raw.Rollback()
	return fn(&Tx{tx: raw, ctx: ctx})
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
