package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"lab02/pkg/models"
)

func TestListSharedOutNotes(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// 1. Create Users
	tokenA := createTestUser(t, server, "alice", "Password123!")
	createTestUser(t, server, "bob", "Password123!") // Just to exist

	// 2. Alice creates a note
	notePayload := map[string]interface{}{
		"title":     "Alice Note",
		"filename":  "alice.txt",
		"content":   []byte("secret content"), // Real handler expects []byte or string for content
		"encrypted": true,
		"shared_keys": map[string][]byte{
			"alice": []byte("owner_encrypted_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)
	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Authorization", "Bearer "+tokenA)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK { // Real handler returns 200 OK on success (check handlers.go)
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}

	var createdNote models.Note
	json.NewDecoder(resp.Body).Decode(&createdNote)
	noteID := createdNote.ID

	// 3. Alice shares note with Bob
	sharePayload := map[string]interface{}{
		"note_id":       noteID,
		"target_user":   "bob",
		"encrypted_key": []byte("dummy_key"),
	}
	shareBody, _ := json.Marshal(sharePayload)
	reqShare, _ := http.NewRequest("POST", server.URL+"/notes/share", bytes.NewBuffer(shareBody))
	reqShare.Header.Set("Authorization", "Bearer "+tokenA)

	respShare, err := client.Do(reqShare)
	if err != nil {
		t.Fatalf("Failed to share note: %v", err)
	}
	defer respShare.Body.Close()

	if respShare.StatusCode != http.StatusOK {
		t.Fatalf("Share failed: %d", respShare.StatusCode)
	}

	// 4. Alice lists shared notes
	reqList, _ := http.NewRequest("GET", server.URL+"/notes/shared-out", nil)
	reqList.Header.Set("Authorization", "Bearer "+tokenA)

	respList, err := client.Do(reqList)
	if err != nil {
		t.Fatalf("Failed to list shared notes: %v", err)
	}
	defer respList.Body.Close()

	if respList.StatusCode != http.StatusOK {
		t.Fatalf("List Shared Out failed: %d", respList.StatusCode)
	}

	var sharedList []models.SharedNoteInfo
	if err := json.NewDecoder(respList.Body).Decode(&sharedList); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// 5. Verify Content
	if len(sharedList) != 1 {
		t.Errorf("Expected 1 shared note, got %d", len(sharedList))
	} else {
		item := sharedList[0]
		if item.NoteID != noteID {
			t.Errorf("Expected NoteID %s, got %s", noteID, item.NoteID)
		}
		if item.SharedWith != "bob" {
			t.Errorf("Expected SharedWith 'bob', got '%s'", item.SharedWith)
		}
		if item.Title != "Alice Note" {
			t.Errorf("Expected Title 'Alice Note', got '%s'", item.Title)
		}
	}
}
