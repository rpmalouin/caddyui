// SPDX-License-Identifier: Apache-2.0

package models_test

import (
	"path/filepath"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Review finding #11 (2026-10-04): a password change/reset must be able to
// evict the sessions minted under the old password. keepToken preserves the
// caller's own session so a self-service password change does not sign the
// user out of the device they are using.
func TestDeleteSessionsForUser(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	userID, err := models.CreateUser(conn, "someone@example.com", "unused-hash", "Someone", models.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	keep, _, err := auth.CreateSession(conn, userID)
	if err != nil {
		t.Fatal(err)
	}
	drop, _, err := auth.CreateSession(conn, userID)
	if err != nil {
		t.Fatal(err)
	}

	if err := models.DeleteSessionsForUser(conn, userID, auth.HashSessionToken(keep)); err != nil {
		t.Fatalf("DeleteSessionsForUser(keep): %v", err)
	}
	if _, err := auth.UserFromSession(conn, keep); err != nil {
		t.Errorf("the kept session should still resolve: %v", err)
	}
	if _, err := auth.UserFromSession(conn, drop); err == nil {
		t.Error("the other session must be revoked")
	}

	if err := models.DeleteSessionsForUser(conn, userID, ""); err != nil {
		t.Fatalf("DeleteSessionsForUser(all): %v", err)
	}
	if _, err := auth.UserFromSession(conn, keep); err == nil {
		t.Error("an empty keepToken must revoke every session")
	}

	// Another user's sessions must be untouched.
	otherID, err := models.CreateUser(conn, "other@example.com", "unused-hash", "Other", models.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	otherTok, _, err := auth.CreateSession(conn, otherID)
	if err != nil {
		t.Fatal(err)
	}
	if err := models.DeleteSessionsForUser(conn, userID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.UserFromSession(conn, otherTok); err != nil {
		t.Errorf("another user's session must survive: %v", err)
	}
}
