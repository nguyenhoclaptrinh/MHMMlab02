package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lab02/pkg/models"
)

type Client struct {
	BaseURL string
	Token   string
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
	}
}

func (c *Client) SetToken(token string) {
	c.Token = token
}

func (c *Client) Register(username, password string, pubKey []byte) error {
	req := struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		PublicKey []byte `json:"public_key"`
	}{
		Username:  username,
		Password:  password,
		PublicKey: pubKey,
	}

	body, _ := json.Marshal(req)
	resp, err := http.Post(c.BaseURL+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("đăng ký thất bại: %s", string(b))
	}
	return nil
}

func (c *Client) Login(username, password string) (*models.AuthResponse, error) {
	req := models.AuthRequest{Username: username, Password: password}
	body, _ := json.Marshal(req)
	resp, err := http.Post(c.BaseURL+"/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("đăng nhập thất bại (Status: %d)", resp.StatusCode)
	}

	var authResp models.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}
	c.Token = authResp.Token
	return &authResp, nil
}

func (c *Client) CreateNote(note models.Note) error {
	body, _ := json.Marshal(note)
	req, _ := http.NewRequest("POST", c.BaseURL+"/notes", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status: %s", resp.Status)
	}
	return nil
}

func (c *Client) ListNotes() ([]models.Note, error) {
	req, _ := http.NewRequest("GET", c.BaseURL+"/notes", nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lỗi lấy danh sách (Status: %s)", resp.Status)
	}

	var notes []models.Note
	err = json.NewDecoder(resp.Body).Decode(&notes)
	return notes, err
}

func (c *Client) GetNote(id string) (*models.Note, error) {
	req, _ := http.NewRequest("GET", c.BaseURL+"/notes/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lỗi đọc ghi chú (Status: %s)", resp.Status)
	}

	var note models.Note
	err = json.NewDecoder(resp.Body).Decode(&note)
	return &note, err
}

func (c *Client) GetUserPublicKey(username string) ([]byte, error) {
	req, _ := http.NewRequest("GET", c.BaseURL+"/users/"+username, nil)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("không tìm thấy user (Status: %s)", resp.Status)
	}

	var uResp struct {
		PublicKey []byte `json:"public_key"`
	}
	err = json.NewDecoder(resp.Body).Decode(&uResp)
	return uResp.PublicKey, err
}

func (c *Client) ShareNote(noteID, targetUser string, encryptedKey []byte) error {
	shareReq := struct {
		NoteID       string `json:"note_id"`
		TargetUser   string `json:"target_user"`
		EncryptedKey []byte `json:"encrypted_key"`
	}{
		NoteID:       noteID,
		TargetUser:   targetUser,
		EncryptedKey: encryptedKey,
	}

	body, _ := json.Marshal(shareReq)
	req, _ := http.NewRequest("POST", c.BaseURL+"/notes/share", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+c.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status: %s", resp.Status)
	}
	return nil
}

func (c *Client) GenerateShareLink(noteID string, maxVisits int, duration string) (string, error) {
	reqLink := struct {
		NoteID    string `json:"note_id"`
		MaxVisits int    `json:"max_visits"`
		Duration  string `json:"duration"`
	}{
		NoteID:    noteID,
		MaxVisits: maxVisits,
		Duration:  duration,
	}
	body, _ := json.Marshal(reqLink)

	r, _ := http.NewRequest("POST", c.BaseURL+"/notes/share-link", bytes.NewBuffer(body))
	r.Header.Set("Authorization", "Bearer "+c.Token)
	r.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%s", string(b))
	}

	var linkResp struct {
		ShareToken string `json:"share_token"`
	}
	json.NewDecoder(resp.Body).Decode(&linkResp)
	return linkResp.ShareToken, nil
}

func (c *Client) GetPublicNote(url string) (*models.Note, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s (Status: %s)", strings.TrimSpace(string(body)), resp.Status)
	}

	var note models.Note
	err = json.NewDecoder(resp.Body).Decode(&note)
	return &note, err
}

func (c *Client) ListSharedOutNotes() ([]models.SharedNoteInfo, error) {
	req, _ := http.NewRequest("GET", c.BaseURL+"/notes/shared-out", nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lỗi lấy danh sách chia sẻ (Status: %s)", resp.Status)
	}

	var notes []models.SharedNoteInfo
	err = json.NewDecoder(resp.Body).Decode(&notes)
	return notes, err
}
