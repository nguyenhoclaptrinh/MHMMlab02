package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"lab02/pkg/models"
)

func TestRevokeShare(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// 1. Create User A (Owner)
	tokenA := createTestUser(t, server, "owneruser", "Pass123!A")

	// 2. Create User B (Target)
	tokenB := createTestUser(t, server, "targetuser", "Pass123!B")

	// 3. User A creates a note
	noteTitle := "Secret Note"
	notePayload := map[string]interface{}{
		"title":   noteTitle,
		"content": base64.StdEncoding.EncodeToString([]byte("Secret Content")),
		"shared_keys": map[string][]byte{
			"owneruser": []byte("dummy_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenA)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteData models.Note
	json.NewDecoder(resp.Body).Decode(&noteData)
	noteID := noteData.ID

	// 4. User A shares with User B
	sharePayload := map[string]interface{}{
		"note_id":       noteID,
		"target_user":   "targetuser",
		"encrypted_key": []byte("dummy_key_for_b"),
	}
	shareBody, _ := json.Marshal(sharePayload)

	reqShare, _ := http.NewRequest("POST", server.URL+"/notes/share", bytes.NewBuffer(shareBody))
	reqShare.Header.Set("Content-Type", "application/json")
	reqShare.Header.Set("Authorization", "Bearer "+tokenA)

	respShare, err := client.Do(reqShare)
	if err != nil || respShare.StatusCode != http.StatusOK {
		t.Fatalf("Failed to share note")
	}
	respShare.Body.Close()

	// 5. Verify User B can see the note
	reqListB, _ := http.NewRequest("GET", server.URL+"/notes", nil)
	reqListB.Header.Set("Authorization", "Bearer "+tokenB)
	respListB, _ := client.Do(reqListB)

	var notesB []models.Note
	json.NewDecoder(respListB.Body).Decode(&notesB)
	found := false
	for _, n := range notesB {
		if n.ID == noteID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("User B should see the shared note")
	}

	// 6. User A Revokes Share (Unshare)
	reqRevoke, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/notes/share?note_id=%s&target_user=targetuser", server.URL, noteID), nil)
	reqRevoke.Header.Set("Authorization", "Bearer "+tokenA)

	respRevoke, err := client.Do(reqRevoke)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer respRevoke.Body.Close()

	if respRevoke.StatusCode != http.StatusOK {
		b, _ := json.Marshal(respRevoke.Body)
		t.Fatalf("Revoke failed with status: %d %s", respRevoke.StatusCode, string(b))
	}

	// 7. Verify User B can NO LONGER see the note
	respListB2, _ := client.Do(reqListB)
	var notesB2 []models.Note
	json.NewDecoder(respListB2.Body).Decode(&notesB2)

	found2 := false
	for _, n := range notesB2 {
		if n.ID == noteID {
			found2 = true
			break
		}
	}
	if found2 {
		t.Fatalf("User B should NOT see the note after revocation")
	}

	t.Log("Revoke Share Test Passed!")
}
