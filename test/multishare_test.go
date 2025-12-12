package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMultiShareLinks(t *testing.T) {
	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	// User A creates a note
	tokenA := createTestUser(t, ctx.Server, "userA", "Password123!")

	// Create Note
	noteID := createNote(t, ctx.Server, tokenA, "userA", "Secret Content")

	// 1. Create Link 1 (Max Visits = 2, Duration = infinite/long)
	shareToken1 := createShareLink(t, ctx.Server, tokenA, noteID, "8760h", 2)

	// 2. Create Link 2 (Expires = 2 seconds)
	shareToken2 := createShareLink(t, ctx.Server, tokenA, noteID, "2s", 0)

	// 3. Verify Link 1 Access (Visit 1 - OK)
	verifyPublicAccess(t, ctx.Server, shareToken1, true)

	// 4. Verify Link 1 Access (Visit 2 - OK)
	verifyPublicAccess(t, ctx.Server, shareToken1, true)

	// 5. Verify Link 1 Access (Visit 3 - Fail - Gone)
	verifyPublicAccess(t, ctx.Server, shareToken1, false)

	// 6. Verify Link 2 Access (Time OK)
	verifyPublicAccess(t, ctx.Server, shareToken2, true)

	// 7. Wait for Link 2 to expire
	time.Sleep(3 * time.Second)

	// 8. Verify Link 2 Access (Time Expired - Fail - Gone)
	verifyPublicAccess(t, ctx.Server, shareToken2, false)

	// 9. Verify Owner can still access note
	verifyOwnerAccess(t, ctx.Server, tokenA, noteID)
}

func createNote(t *testing.T, server *httptest.Server, token string, username string, content string) string {
	return execRequest(t, server, "POST", "/notes", token, map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"shared_keys": map[string][]byte{
			username: []byte("dummy_key"),
		},
	}, func(resp map[string]interface{}) string {
		return resp["id"].(string)
	})
}

func createShareLink(t *testing.T, server *httptest.Server, token string, noteID string, duration string, maxVisits int) string {
	return execRequest(t, server, "POST", "/notes/share-link", token, map[string]interface{}{
		"note_id":    noteID,
		"duration":   duration,
		"max_visits": maxVisits,
	}, func(resp map[string]interface{}) string {
		return resp["share_token"].(string)
	})
}

func verifyPublicAccess(t *testing.T, server *httptest.Server, shareToken string, expectSuccess bool) {
	resp, err := http.Get(server.URL + "/public/notes/" + shareToken)
	if err != nil {
		t.Fatalf("Failed to get public note: %v", err)
	}
	defer resp.Body.Close()

	if expectSuccess {
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK, got %d", resp.StatusCode)
		}
	} else {
		if resp.StatusCode != http.StatusGone && resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status Gone/NotFound, got %d", resp.StatusCode)
		}
	}
}

func verifyOwnerAccess(t *testing.T, server *httptest.Server, token string, noteID string) {
	req, _ := http.NewRequest("GET", server.URL+"/notes/"+noteID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Owner access check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Owner should still have access, got status %d", resp.StatusCode)
	}
}

// Helper to execute request and parse simple JSON response
func execRequest(t *testing.T, server *httptest.Server, method, path, token string, body interface{}, extractor func(map[string]interface{}) string) string {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, server.URL+path, bytes.NewBuffer(b))
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request %s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("Request %s %s returned status %d", method, path, resp.StatusCode)
	}

	var respMap map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respMap)
	if extractor != nil {
		return extractor(respMap)
	}
	return ""
}
