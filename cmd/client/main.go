package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"encoding/hex"
	"strings"

	"lab02/pkg/crypto"
	"lab02/pkg/models"

	"github.com/manifoldco/promptui"
)

const (
	ServerURL = "http://localhost:8080"
)

// Current session
var (
	authToken   string
	currentUser models.User
	privKey     *ecdh.PrivateKey
)

func main() {
	// Giới thiệu đơn giản
	fmt.Println("Ứng dụng chia sẻ ghi chú bảo mật")

	for {
		if authToken == "" {
			fmt.Println("\n--- CHÀO MỪNG ---")
			fmt.Println("1. Đăng nhập")
			fmt.Println("2. Đăng ký")
			fmt.Println("3. Tải từ Link")
			fmt.Println("4. Thoát")

			prompt := promptui.Prompt{Label: "Nhập lựa chọn"}
			result, _ := prompt.Run()

			switch result {
			case "1":
				login()
			case "2":
				register()
			case "3":
				downloadFromUrl()
			case "4":
				return
			default:
				fmt.Println("Lựa chọn không hợp lệ.")
			}
		} else {
			mainMenu()
		}
	}
}

func register() {
	prompt := promptui.Prompt{Label: "Tên đăng nhập"}
	username, _ := prompt.Run()
	prompt = promptui.Prompt{Label: "Mật khẩu", Mask: '*'}
	password, _ := prompt.Run()

	fmt.Println("Đang tạo cặp khóa ECDH (Diffie-Hellman)...")
	pk, pubBytes, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		fmt.Printf("Lỗi tạo khóa: %v\n", err)
		return
	}
	fmt.Println("Thành công! Đã tạo khóa bí mật.")
	req := struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		PublicKey []byte `json:"public_key"`
	}{
		Username:  username,
		Password:  password,
		PublicKey: pubBytes,
	}

	body, _ := json.Marshal(req)
	fmt.Println("Đang gửi yêu cầu đăng ký tới server...")
	resp, err := http.Post(ServerURL+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("Lỗi kết nối: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		fmt.Println("Đăng ký thành công! Đang lưu khóa bí mật...")
		// Lưu khóa bí mật cục bộ
		err := os.WriteFile(username+".pem", crypto.EncodeECDHPrivateKey(pk), 0600)
		if err != nil {
			fmt.Printf("Cảnh báo: Không thể lưu khóa bí mật: %v\n", err)
		} else {
			fmt.Println("Khóa bí mật đã được lưu tại " + username + ".pem")
		}
	} else {
		b, _ := io.ReadAll(resp.Body)
		fmt.Printf("Đăng ký thất bại: %s\n", string(b))
	}
}

func login() {
	prompt := promptui.Prompt{Label: "Tên đăng nhập"}
	username, _ := prompt.Run()
	prompt = promptui.Prompt{Label: "Mật khẩu", Mask: '*'}
	password, _ := prompt.Run()

	req := models.AuthRequest{Username: username, Password: password}
	body, _ := json.Marshal(req)
	fmt.Println("Đang thử đăng nhập...")
	resp, err := http.Post(ServerURL+"/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("Lỗi kết nối: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Đăng nhập thất bại.")
		return
	}

	var authResp models.AuthResponse
	json.NewDecoder(resp.Body).Decode(&authResp)

	authToken = authResp.Token
	currentUser = authResp.User

	fmt.Printf("Đăng nhập thành công. Token: %s...\n", authToken[:10])

	// Tải khóa bí mật
	fmt.Printf("Đang tải khóa bí mật từ %s.pem...\n", username)
	pemData, err := os.ReadFile(username + ".pem")
	if err != nil {
		fmt.Printf("Không thể tải khóa bí mật (%s). Bạn sẽ không thể giải mã ghi chú.\n", err)
	} else {
		privKey, err = crypto.ParseECDHPrivateKey(pemData)
		if err != nil {
			fmt.Printf("Khóa bí mật không hợp lệ: %v\n", err)
		} else {
			fmt.Println("Đã tải khóa bí mật thành công.")
		}
	}

	fmt.Printf("Chào mừng, %s!\n", currentUser.Username)
}

func mainMenu() {
	fmt.Println("\n--- MENU ---")
	fmt.Println("1. Tạo ghi chú")
	fmt.Println("2. Liệt kê ghi chú")
	fmt.Println("3. Xem ghi chú")
	fmt.Println("4. Chia sẻ ghi chú")
	fmt.Println("5. Chia sẻ qua Link")
	fmt.Println("6. Tải từ Link")
	fmt.Println("7. Xóa ghi chú")
	fmt.Println("8. Đăng xuất")
	fmt.Println("9. Thoát")

	prompt := promptui.Prompt{Label: "Nhập lựa chọn"}
	result, _ := prompt.Run()

	switch result {
	case "1":
		createNote()
	case "2":
		listNotes()
	case "3":
		readNote()
	case "4":
		shareNote()
	case "5":
		shareViaUrl()
	case "6":
		downloadFromUrl()
	case "7":
		deleteNote()
	case "8":
		authToken = ""
		currentUser = models.User{}
		privKey = nil
	case "9":
		os.Exit(0)
	default:
		fmt.Println("Lựa chọn không hợp lệ.")
	}
}

func createNote() {
	if privKey == nil {
		fmt.Println("Không thể tạo ghi chú nếu không có khóa bí mật (cần nó để giải mã sau này).")
		return
	}

	titlePromt := promptui.Prompt{Label: "Tiêu đề ghi chú"}
	title, _ := titlePromt.Run()

	filePrompt := promptui.Prompt{Label: "Đường dẫn file cần upload"}
	filePath, _ := filePrompt.Run()

	// Đọc nội dung file
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Lỗi đọc file: %v\n", err)
		return
	}

	// Lấy tên file gốc
	// Cần import "path/filepath", nhưng ở đây dùng logic đơn giản hoặc thêm import sau.
	// Để đơn giản, giả sử người dùng nhập đường dẫn, ta lấy phần cuối.
	// Tuy nhiên để code chạy ngay mà không sửa import, ta dùng string manipulation đơn giản
	// hoặc tốt nhất là thêm "path/filepath" vào import block.
	// Hiện tại chưa có filepath, ta sẽ thêm vào replacement chunk tiếp theo hoặc dùng cách thủ công.
	// Cách thủ công:
	filename := filePath
	for i := len(filePath) - 1; i >= 0; i-- {
		if os.IsPathSeparator(filePath[i]) {
			filename = filePath[i+1:]
			break
		}
	}

	// Tạo khóa mã hóa AES cho ghi chú
	fmt.Println("Đang tạo khóa AES ngẫu nhiên cho ghi chú...")
	aesKey, err := crypto.GenerateAESKey()
	if err != nil {
		log.Println(err)
		return
	}

	// Mã hóa nội dung
	fmt.Println("Đang mã hóa nội dung file bằng khóa AES...")
	encContent, err := crypto.EncryptAES(fileContent, aesKey)
	if err != nil {
		log.Println(err)
		return
	}

	// Mã hóa khóa cho chính mình
	fmt.Println("Đang mã hóa khóa AES bằng Shared Secret (với chính mình)...")

	// Derive Shared Secret với chính mình
	sharedSecret, err := crypto.DeriveSharedKey(privKey, currentUser.PublicKey)
	if err != nil {
		log.Println("Lỗi tạo shared secret:", err)
		return
	}

	encKey, err := crypto.EncryptAES(aesKey, sharedSecret)
	if err != nil {
		log.Println("Lỗi mã hóa khóa AES:", err)
		return
	}

	note := models.Note{
		Title:     title,
		Filename:  filename,
		Content:   encContent,
		Encrypted: true,
		OwnerID:   currentUser.ID,
		SharedKeys: map[string][]byte{
			currentUser.ID: encKey,
		},
	}

	sendNote(note)
}

func sendNote(note models.Note) {
	body, _ := json.Marshal(note)
	req, _ := http.NewRequest("POST", ServerURL+"/notes", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Đã tạo ghi chú thành công.")
	} else {
		fmt.Printf("Thất bại: %s\n", resp.Status)
	}
}

func listNotes() {
	req, _ := http.NewRequest("GET", ServerURL+"/notes", nil)
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	var notes []models.Note
	json.NewDecoder(resp.Body).Decode(&notes)

	fmt.Println("\n--- Danh sách ghi chú ---")
	for _, n := range notes {
		access := "Được chia sẻ"
		if n.OwnerID == currentUser.ID {
			access = "Chủ sở hữu"
		}
		fmt.Printf("[%s] %s (%s) [%s]\n", n.ID, n.Title, n.Filename, access)
	}
	fmt.Println("-------------------------")
}

func readNote() {
	prompt := promptui.Prompt{Label: "Note ID"}
	id, _ := prompt.Run()

	req, _ := http.NewRequest("GET", ServerURL+"/notes/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Lỗi đọc ghi chú")
		return
	}

	var note models.Note
	json.NewDecoder(resp.Body).Decode(&note)

	if !note.Encrypted {
		fmt.Println("Ghi chú không được mã hóa (phiên bản cũ?)")
		fmt.Println(string(note.Content))
		return
	}

	if privKey == nil {
		fmt.Println("Chưa tải khóa bí mật để giải mã ghi chú này.")
		return
	}

	// Lấy khóa mã hóa cho tôi
	encKey, ok := note.SharedKeys[currentUser.ID]
	if !ok {
		fmt.Println("Bạn không có khóa cho ghi chú này.")
		return
	}

	// Để giải mã khóa AES, ta cần Shared Secret.
	// Shared Secret = ECDH(MyPriv, OwnerPub).
	// Nếu tôi là owner, OwnerPub = currentUser.PublicKey.
	// Nếu người khác chia sẻ cho tôi, tôi cần lấy Public Key của họ (Owner).

	var ownerPub []byte
	if note.OwnerID == currentUser.ID {
		ownerPub = currentUser.PublicKey
	} else {
		// Fetch Owner Public Key
		reqU, _ := http.NewRequest("GET", ServerURL+"/users/"+note.OwnerID, nil)
		respU, err := client.Do(reqU)
		if err != nil || respU.StatusCode != http.StatusOK {
			fmt.Printf("Không thể lấy Public Key của chủ sở hữu (%s).\n", note.OwnerID)
			return
		}
		defer respU.Body.Close()
		var uResp struct {
			PublicKey []byte `json:"public_key"`
		}
		json.NewDecoder(respU.Body).Decode(&uResp)
		ownerPub = uResp.PublicKey
	}

	// Derive Secret
	sharedSecret, err := crypto.DeriveSharedKey(privKey, ownerPub)
	if err != nil {
		fmt.Printf("Lỗi tạo shared secret: %v\n", err)
		return
	}

	// Giải mã khóa AES (dùng AES decrypt với key là SharedSecret)
	aesKey, err := crypto.DecryptAES(encKey, sharedSecret)
	if err != nil {
		fmt.Printf("Lỗi giải mã khóa AES: %v\n", err)
		return
	}

	// Giải mã nội dung
	plaintext, err := crypto.DecryptAES(note.Content, aesKey)
	if err != nil {
		fmt.Printf("Lỗi giải mã nội dung: %v\n", err)
		return
	}

	defaultFilename := note.Filename
	if defaultFilename == "" {
		defaultFilename = "downloaded_note.txt"
	}

	filePrompt := promptui.Prompt{
		Label:   "Lưu thành file (Enter để dùng tên gốc)",
		Default: defaultFilename,
	}
	outPath, _ := filePrompt.Run()

	err = os.WriteFile(outPath, plaintext, 0644)
	if err != nil {
		fmt.Printf("Lỗi lưu file: %v\n", err)
		return
	}

	fmt.Printf("\n--- Tải file thành công ---\n")
	fmt.Printf("Tiêu đề: %s\n", note.Title)
	fmt.Printf("File gốc: %s\n", note.Filename)
	fmt.Printf("Đã lưu tại: %s\n", outPath)
	fmt.Println("---------------------------")
}

func shareNote() {
	prompt := promptui.Prompt{Label: "Note ID"}
	noteID, _ := prompt.Run()

	prompt = promptui.Prompt{Label: "Tên người nhận"}
	targetUser, _ := prompt.Run()

	// 1. Lấy Public Key của người nhận
	req, _ := http.NewRequest("GET", ServerURL+"/users/"+targetUser, nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("Không tìm thấy người dùng hoặc lỗi.")
		return
	}

	var userResp struct {
		PublicKey []byte `json:"public_key"`
	}
	json.NewDecoder(resp.Body).Decode(&userResp)
	fmt.Printf("Tìm thấy người dùng %s. Đã phát hiện Public Key.\n", targetUser)

	// 2. Lấy ghi chú (để lấy khóa AES)
	reqNote, _ := http.NewRequest("GET", ServerURL+"/notes/"+noteID, nil)
	reqNote.Header.Set("Authorization", "Bearer "+authToken)
	respNote, err := client.Do(reqNote)
	if err != nil || respNote.StatusCode != http.StatusOK {
		fmt.Println("Không thể lấy chi tiết ghi chú.")
		return
	}

	var note models.Note
	json.NewDecoder(respNote.Body).Decode(&note)

	// 3. Giải mã khóa AES
	myEncKey, ok := note.SharedKeys[currentUser.ID]
	if !ok {
		fmt.Println("Bạn không có quyền truy cập ghi chú này.")
		return
	}
	// Helper function usage tricky here without duplication, but OK for now inline.
	var ownerPub []byte
	if note.OwnerID == currentUser.ID {
		ownerPub = currentUser.PublicKey
	} else {
		reqU, _ := http.NewRequest("GET", ServerURL+"/users/"+note.OwnerID, nil)
		respU, err := client.Do(reqU)
		if err != nil || respU.StatusCode != http.StatusOK {
			fmt.Println("Không thể lấy Public Key chủ sở hữu.")
			return
		}
		defer respU.Body.Close()
		var uResp struct {
			PublicKey []byte `json:"public_key"`
		}
		json.NewDecoder(respU.Body).Decode(&uResp)
		ownerPub = uResp.PublicKey
	}

	sharedSecret, err := crypto.DeriveSharedKey(privKey, ownerPub)
	if err != nil {
		fmt.Println("Lỗi shared secret.")
		return
	}

	aesKey, err := crypto.DecryptAES(myEncKey, sharedSecret)
	if err != nil {
		fmt.Println("Không thể giải mã khóa.")
		return
	}

	// 4. Mã hóa khóa AES cho người nhận
	// Cần Shared Secret = ECDH(MyPriv, TargetPub)
	sharedSecret, err = crypto.DeriveSharedKey(privKey, userResp.PublicKey)
	if err != nil {
		fmt.Println("Lỗi tạo shared secret với người nhận.")
		return
	}

	targetEncKey, err := crypto.EncryptAES(aesKey, sharedSecret)
	if err != nil {
		fmt.Println("Không thể mã hóa khóa cho người nhận.")
		return
	}

	// 5. Gửi yêu cầu chia sẻ
	shareReq := struct {
		NoteID       string `json:"note_id"`
		TargetUser   string `json:"target_user"`
		EncryptedKey []byte `json:"encrypted_key"`
	}{
		NoteID:       noteID,
		TargetUser:   targetUser,
		EncryptedKey: targetEncKey,
	}

	body, _ := json.Marshal(shareReq)
	reqShare, _ := http.NewRequest("POST", ServerURL+"/notes/share", bytes.NewBuffer(body))
	reqShare.Header.Set("Authorization", "Bearer "+authToken)

	respShare, err := client.Do(reqShare)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer respShare.Body.Close()

	if respShare.StatusCode == http.StatusOK {
		fmt.Println("Đã chia sẻ ghi chú thành công!")
	} else {
		fmt.Println("Chia sẻ thất bại: " + respShare.Status)
	}
}

func shareViaUrl() {
	prompt := promptui.Prompt{Label: "Note ID"}
	noteID, _ := prompt.Run()

	reqNote, _ := http.NewRequest("GET", ServerURL+"/notes/"+noteID, nil)
	reqNote.Header.Set("Authorization", "Bearer "+authToken)
	client := &http.Client{}
	respNote, err := client.Do(reqNote)
	if err != nil || respNote.StatusCode != http.StatusOK {
		fmt.Println("Không thể lấy thông tin ghi chú.")
		return
	}
	var note models.Note
	json.NewDecoder(respNote.Body).Decode(&note)

	// Lấy khóa AES
	myEncKey, ok := note.SharedKeys[currentUser.ID]
	if !ok {
		fmt.Println("Bạn không có quyền truy cập ghi chú này.")
		return
	}
	// Helper function usage tricky here without duplication, but OK for now inline.
	var ownerPub []byte
	if note.OwnerID == currentUser.ID {
		ownerPub = currentUser.PublicKey
	} else {
		reqU, _ := http.NewRequest("GET", ServerURL+"/users/"+note.OwnerID, nil)
		respU, err := client.Do(reqU)
		if err != nil || respU.StatusCode != http.StatusOK {
			fmt.Println("Không thể lấy Public Key chủ sở hữu.")
			return
		}
		defer respU.Body.Close()
		var uResp struct {
			PublicKey []byte `json:"public_key"`
		}
		json.NewDecoder(respU.Body).Decode(&uResp)
		ownerPub = uResp.PublicKey
	}

	sharedSecret, err := crypto.DeriveSharedKey(privKey, ownerPub)
	if err != nil {
		fmt.Println("Lỗi shared secret.")
		return
	}

	aesKey, err := crypto.DecryptAES(myEncKey, sharedSecret)
	if err != nil {
		fmt.Println("Không thể giải mã khóa.")
		return
	}

	// Gửi yêu cầu tạo token
	reqLink := struct {
		NoteID string `json:"note_id"`
	}{NoteID: noteID}
	body, _ := json.Marshal(reqLink)

	r, _ := http.NewRequest("POST", ServerURL+"/notes/share-link", bytes.NewBuffer(body))
	r.Header.Set("Authorization", "Bearer "+authToken)
	r.Header.Set("Content-Type", "application/json")

	client = &http.Client{}
	respLink, err := client.Do(r)
	if err != nil {
		fmt.Println("Lỗi kết nối server.")
		return
	}
	defer respLink.Body.Close()

	if respLink.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respLink.Body)
		fmt.Printf("Lỗi tạo link: %s (Status: %d)\n", string(body), respLink.StatusCode)
		return
	}

	var linkResp struct {
		ShareToken string `json:"share_token"`
	}
	json.NewDecoder(respLink.Body).Decode(&linkResp)

	// Tạo URL: ServerURL/public/notes/{token}#{hex(aesKey)}
	aesKeyHex := hex.EncodeToString(aesKey)
	fullLink := fmt.Sprintf("%s/public/notes/%s#%s", ServerURL, linkResp.ShareToken, aesKeyHex)

	fmt.Println("--- LINK CHIA SẺ ---")
	fmt.Println(fullLink)
	fmt.Println("(Gửi link này cho người nhận. Họ có thể tải file mà không cần tài khoản)")
	fmt.Println("--------------------")
}

func downloadFromUrl() {
	prompt := promptui.Prompt{Label: "Nhập Link chia sẻ"}
	inputLink, _ := prompt.Run()

	// Parse link: Link#Key
	parts := strings.Split(inputLink, "#")
	if len(parts) != 2 {
		fmt.Println("Link không hợp lệ (thiếu phần Key sau dấu #).")
		return
	}
	urlPart := parts[0]
	keyHex := parts[1]

	aesKey, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Println("Key trong link lỗi format Hex.")
		return
	}

	// Tải ghi chú từ server (public endpoint)
	resp, err := http.Get(urlPart)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("Không thể tải ghi chú từ link (hoặc link sai/hết hạn).")
		return
	}
	defer resp.Body.Close()

	var note models.Note
	json.NewDecoder(resp.Body).Decode(&note)

	// Giải mã content
	plaintext, err := crypto.DecryptAES(note.Content, aesKey)
	if err != nil {
		fmt.Printf("Lỗi giải mã nội dung: %v\n", err)
		return
	}

	// Lưu file
	defaultFilename := note.Filename
	if defaultFilename == "" {
		defaultFilename = "downloaded_via_link.txt"
	}

	filePrompt := promptui.Prompt{
		Label:   "Lưu thành file (Enter để dùng tên gốc)",
		Default: defaultFilename,
	}
	outPath, _ := filePrompt.Run()

	err = os.WriteFile(outPath, plaintext, 0644)
	if err != nil {
		fmt.Printf("Lỗi lưu file: %v\n", err)
		return
	}

	fmt.Printf("\n--- Tải file thành công ---\n")
	fmt.Printf("Tiêu đề: %s\n", note.Title)
	fmt.Printf("File gốc: %s\n", note.Filename)
	fmt.Printf("Đã lưu tại: %s\n", outPath)
	fmt.Println("---------------------------")
}

func deleteNote() {
	prompt := promptui.Prompt{Label: "Note ID cần xóa"}
	id, _ := prompt.Run()

	req, _ := http.NewRequest("DELETE", ServerURL+"/notes?id="+id, nil)
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Lỗi kết nối:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Đã xóa ghi chú thành công!")
	} else if resp.StatusCode == http.StatusForbidden {
		fmt.Println("Xóa thất bại: Bạn không phải chủ sở hữu.")
	} else if resp.StatusCode == http.StatusNotFound {
		fmt.Println("Xóa thất bại: Không tìm thấy ghi chú.")
	} else {
		fmt.Println("Lỗi xóa ghi chú:", resp.Status)
	}
}
