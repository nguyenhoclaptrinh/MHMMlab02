package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	_ "modernc.org/sqlite"
)

// Test Cases cho Access Control và Share Links

// TestShareNoteWithAnotherUser kiểm tra chia sẻ note với user khác
func TestShareNoteWithAnotherUser(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// Tạo 2 users
	token1 := createTestUser(t, server, "owner", "Password123!")
	token2 := createTestUser(t, server, "recipient", "Password123!")

	// User 1 tạo note
	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte("Shared secret note")),
		"shared_keys": map[string][]byte{
			"owner": []byte("dummy_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token1)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// Share note với user 2
	sharePayload := map[string]interface{}{
		"note_id":       noteID,
		"target_user":   "recipient",
		"encrypted_key": []byte("validbase64key=="),
	}
	shareBody, _ := json.Marshal(sharePayload)

	shareReq, _ := http.NewRequest("POST", server.URL+"/notes/share", bytes.NewBuffer(shareBody))
	shareReq.Header.Set("Content-Type", "application/json")
	shareReq.Header.Set("Authorization", "Bearer "+token1)

	shareResp, err := client.Do(shareReq)
	if err != nil {
		t.Fatalf("Failed to share note: %v", err)
	}
	defer shareResp.Body.Close()

	if shareResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", shareResp.StatusCode)
	}

	// User 2 access note
	getReq, _ := http.NewRequest("GET", server.URL+"/notes/"+noteID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token2)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to get shared note: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Errorf("Expected user 2 to access shared note, got status %d", getResp.StatusCode)
	}
}

// TestShareLinkGeneration kiểm tra tạo share link
func TestShareLinkGeneration(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token := createTestUser(t, server, "linkcreator", "Password123!")

	// Tạo note
	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte("Note with share link")),
		"shared_keys": map[string][]byte{
			"linkcreator": []byte("dummy_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// Tạo share link
	linkPayload := map[string]interface{}{
		"note_id":  noteID,
		"duration": "24h",
	}
	linkBody, _ := json.Marshal(linkPayload)

	linkReq, _ := http.NewRequest("POST", server.URL+"/notes/share-link", bytes.NewBuffer(linkBody))
	linkReq.Header.Set("Content-Type", "application/json")
	linkReq.Header.Set("Authorization", "Bearer "+token)

	linkResp, err := client.Do(linkReq)
	if err != nil {
		t.Fatalf("Failed to generate share link: %v", err)
	}
	defer linkResp.Body.Close()

	if linkResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", linkResp.StatusCode)
	}

	var linkRespData map[string]interface{}
	json.NewDecoder(linkResp.Body).Decode(&linkRespData)
	if linkRespData["share_token"] == nil {
		t.Error("Expected share_token in response")
	}
}

// TestAccessPublicNote kiểm tra access public note via share link
func TestAccessPublicNote(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token := createTestUser(t, server, "publicnoteuser", "Password123!")

	// Tạo note
	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte("Public accessible note")),
		"shared_keys": map[string][]byte{
			"publicnoteuser": []byte("dummy_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// Tạo share link
	linkPayload := map[string]interface{}{
		"note_id":  noteID,
		"duration": "24h",
	}
	linkBody, _ := json.Marshal(linkPayload)

	linkReq, _ := http.NewRequest("POST", server.URL+"/notes/share-link", bytes.NewBuffer(linkBody))
	linkReq.Header.Set("Content-Type", "application/json")
	linkReq.Header.Set("Authorization", "Bearer "+token)

	linkResp, err := client.Do(linkReq)
	if err != nil {
		t.Fatalf("Failed to generate share link: %v", err)
	}
	defer linkResp.Body.Close()

	var linkData map[string]interface{}
	json.NewDecoder(linkResp.Body).Decode(&linkData)
	shareToken := linkData["share_token"].(string)

	// Access note qua public URL (không cần auth)
	publicReq, _ := http.NewRequest("GET", server.URL+"/public/notes/"+shareToken, nil)
	publicResp, err := client.Do(publicReq)
	if err != nil {
		t.Fatalf("Failed to access public note: %v", err)
	}
	defer publicResp.Body.Close()

	if publicResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for public access, got %d", publicResp.StatusCode)
	}
}

// TestExpiredShareLink kiểm tra expired share link
func TestExpiredShareLink(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token := createTestUser(t, server, "expireduser", "Password123!")

	// Tạo note
	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte("Expired note")),
		"shared_keys": map[string][]byte{
			"expireduser": []byte("dummy_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// Tạo share link đã expired (1 giây trước)
	linkPayload := map[string]interface{}{
		"note_id":  noteID,
		"duration": "-1s",
	}
	linkBody, _ := json.Marshal(linkPayload)

	linkReq, _ := http.NewRequest("POST", server.URL+"/notes/share-link", bytes.NewBuffer(linkBody))
	linkReq.Header.Set("Content-Type", "application/json")
	linkReq.Header.Set("Authorization", "Bearer "+token)

	linkResp, err := client.Do(linkReq)
	if err != nil {
		t.Fatalf("Failed to generate share link: %v", err)
	}
	defer linkResp.Body.Close()

	var linkData map[string]interface{}
	json.NewDecoder(linkResp.Body).Decode(&linkData)
	shareToken := linkData["share_token"].(string)

	// Thử access expired note
	publicReq, _ := http.NewRequest("GET", server.URL+"/public/notes/"+shareToken, nil)
	publicResp, err := client.Do(publicReq)
	if err != nil {
		t.Fatalf("Failed to access public note: %v", err)
	}
	defer publicResp.Body.Close()

	if publicResp.StatusCode != http.StatusGone {
		t.Errorf("Expected status 410 (Gone) for expired note, got %d", publicResp.StatusCode)
	}
}

// TestUnauthorizedNoteAccess kiểm tra không thể access note của người khác
func TestUnauthorizedNoteAccess(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token1 := createTestUser(t, server, "user1", "Password123!")
	token2 := createTestUser(t, server, "user2", "Password123!")

	// User 1 tạo note
	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte("Private note")),
		"shared_keys": map[string][]byte{
			"user1": []byte("dummy_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token1)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// User 2 thử access note (chưa share)
	getReq, _ := http.NewRequest("GET", server.URL+"/notes/"+noteID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token2)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusForbidden && getResp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 403 or 404 for unauthorized access, got %d", getResp.StatusCode)
	}
}
