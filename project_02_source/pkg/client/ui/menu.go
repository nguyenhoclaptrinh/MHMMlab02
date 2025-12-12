package ui

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"lab02/pkg/client/api"
	"lab02/pkg/client/crypto"
	"lab02/pkg/models"

	"github.com/manifoldco/promptui"
)

type App struct {
	Client      *api.Client
	CurrentUser models.User
	PrivKey     *ecdh.PrivateKey
}

func NewApp(client *api.Client) *App {
	return &App{Client: client}
}

func (app *App) Run() {
	fmt.Println("Ứng dụng chia sẻ ghi chú bảo mật")
	for {
		if app.Client.Token == "" {
			app.unauthMenu()
		} else {
			app.authMenu()
		}
	}
}

func (app *App) unauthMenu() {
	fmt.Println("\n--- CHÀO MỪNG ---")
	fmt.Println("1. Đăng nhập")
	fmt.Println("2. Đăng ký")
	fmt.Println("3. Tải từ Link")
	fmt.Println("4. Thoát")

	prompt := promptui.Prompt{Label: "Nhập lựa chọn"}
	result, _ := prompt.Run()

	switch result {
	case "1":
		app.login()
	case "2":
		app.register()
	case "3":
		app.downloadFromUrl()
	case "4":
		os.Exit(0)
	default:
		fmt.Println("Lựa chọn không hợp lệ.")
	}
}

func (app *App) authMenu() {
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
		app.createNote()
	case "2":
		app.listNotes()
	case "3":
		app.readNote()
	case "4":
		app.shareNote()
	case "5":
		app.shareViaUrl()
	case "6":
		app.downloadFromUrl()
	case "7":
		app.deleteNote()
	case "8":
		app.Client.SetToken("")
		app.CurrentUser = models.User{}
		app.PrivKey = nil
	case "9":
		os.Exit(0)
	default:
		fmt.Println("Lựa chọn không hợp lệ.")
	}
}

func (app *App) register() {
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

	err = app.Client.Register(username, password, pubBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Đăng ký thành công! Đang lưu khóa bí mật...")
	err = os.WriteFile(username+".pem", crypto.EncodeECDHPrivateKey(pk), 0600)
	if err != nil {
		fmt.Printf("Cảnh báo: Không thể lưu khóa bí mật: %v\n", err)
	} else {
		fmt.Println("Khóa bí mật đã được lưu tại " + username + ".pem")
	}
}

func (app *App) login() {
	prompt := promptui.Prompt{Label: "Tên đăng nhập"}
	username, _ := prompt.Run()
	prompt = promptui.Prompt{Label: "Mật khẩu", Mask: '*'}
	password, _ := prompt.Run()

	fmt.Println("Đang thử đăng nhập...")
	resp, err := app.Client.Login(username, password)
	if err != nil {
		fmt.Println(err)
		return
	}

	app.CurrentUser = resp.User
	fmt.Printf("Đăng nhập thành công. Token: %s...\n", app.Client.Token[:10])

	fmt.Printf("Đang tải khóa bí mật từ %s.pem...\n", username)
	pemData, err := os.ReadFile(username + ".pem")
	if err != nil {
		fmt.Printf("Không thể tải khóa bí mật (%s). Bạn sẽ không thể giải mã ghi chú.\n", err)
	} else {
		app.PrivKey, err = crypto.ParseECDHPrivateKey(pemData)
		if err != nil {
			fmt.Printf("Khóa bí mật không hợp lệ: %v\n", err)
		} else {
			fmt.Println("Đã tải khóa bí mật thành công.")
		}
	}
	fmt.Printf("Chào mừng, %s!\n", app.CurrentUser.Username)
}

func (app *App) createNote() {
	if app.PrivKey == nil {
		fmt.Println("Không thể tạo ghi chú nếu không có khóa bí mật.")
		return
	}

	titlePromt := promptui.Prompt{Label: "Tiêu đề ghi chú"}
	title, _ := titlePromt.Run()

	filePrompt := promptui.Prompt{Label: "Đường dẫn file cần upload"}
	filePath, _ := filePrompt.Run()

	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Lỗi đọc file: %v\n", err)
		return
	}

	// Filename logic
	filename := filePath
	for i := len(filePath) - 1; i >= 0; i-- {
		if os.IsPathSeparator(filePath[i]) {
			filename = filePath[i+1:]
			break
		}
	}

	fmt.Println("Đang tạo khóa AES ngẫu nhiên cho ghi chú...")
	aesKey, err := crypto.GenerateAESKey()
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Đang mã hóa nội dung file bằng khóa AES...")
	encContent, err := crypto.EncryptAES(fileContent, aesKey)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Đang mã hóa khóa AES bằng Shared Secret (với chính mình)...")
	sharedSecret, err := crypto.DeriveSharedKey(app.PrivKey, app.CurrentUser.PublicKey)
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
		OwnerID:   app.CurrentUser.ID,
		SharedKeys: map[string][]byte{
			app.CurrentUser.ID: encKey,
		},
	}

	if err := app.Client.CreateNote(note); err != nil {
		fmt.Println("Lỗi tạo ghi chú:", err)
	} else {
		fmt.Println("Đã tạo ghi chú thành công.")
	}
}

func (app *App) listNotes() {
	notes, err := app.Client.ListNotes()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("\n--- Danh sách ghi chú ---")
	for _, n := range notes {
		access := "Được chia sẻ"
		if n.OwnerID == app.CurrentUser.ID {
			access = "Chủ sở hữu"
		}
		fmt.Printf("[%s] %s (%s) [%s]\n", n.ID, n.Title, n.Filename, access)
	}
	fmt.Println("-------------------------")
}

func (app *App) readNote() {
	prompt := promptui.Prompt{Label: "Note ID"}
	id, _ := prompt.Run()

	note, err := app.Client.GetNote(id)
	if err != nil {
		fmt.Println(err)
		return
	}

	if !note.Encrypted {
		fmt.Println("Ghi chú không được mã hóa:")
		fmt.Println(string(note.Content))
		return
	}

	if app.PrivKey == nil {
		fmt.Println("Chưa tải khóa bí mật để giải mã.")
		return
	}

	encKey, ok := note.SharedKeys[app.CurrentUser.ID]
	if !ok {
		fmt.Println("Bạn không có khóa cho ghi chú này.")
		return
	}

	var ownerPub []byte
	if note.OwnerID == app.CurrentUser.ID {
		ownerPub = app.CurrentUser.PublicKey
	} else {
		ownerPub, err = app.Client.GetUserPublicKey(note.OwnerID)
		if err != nil {
			fmt.Printf("Lỗi lấy public key chủ sở hữu: %v\n", err)
			return
		}
	}

	sharedSecret, err := crypto.DeriveSharedKey(app.PrivKey, ownerPub)
	if err != nil {
		fmt.Printf("Lỗi tạo shared secret: %v\n", err)
		return
	}

	aesKey, err := crypto.DecryptAES(encKey, sharedSecret)
	if err != nil {
		fmt.Printf("Lỗi giải mã khóa AES: %v\n", err)
		return
	}

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

	if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
		fmt.Printf("Lỗi lưu file: %v\n", err)
	} else {
		fmt.Printf("\n--- Tải file thành công ---\n")
		fmt.Printf("Tiêu đề: %s\n", note.Title)
		fmt.Printf("Đã lưu tại: %s\n", outPath)
		fmt.Println("---------------------------")
	}
}

func (app *App) shareNote() {
	prompt := promptui.Prompt{Label: "Note ID"}
	noteID, _ := prompt.Run()

	prompt = promptui.Prompt{Label: "Tên người nhận"}
	targetUser, _ := prompt.Run()

	targetPub, err := app.Client.GetUserPublicKey(targetUser)
	if err != nil {
		fmt.Println("Không tìm thấy người dùng:", err)
		return
	}

	note, err := app.Client.GetNote(noteID)
	if err != nil {
		fmt.Println("Không thể lấy chi tiết ghi chú:", err)
		return
	}

	myEncKey, ok := note.SharedKeys[app.CurrentUser.ID]
	if !ok {
		fmt.Println("Bạn không có quyền truy cập ghi chú này.")
		return
	}

	var ownerPub []byte
	if note.OwnerID == app.CurrentUser.ID {
		ownerPub = app.CurrentUser.PublicKey
	} else {
		ownerPub, err = app.Client.GetUserPublicKey(note.OwnerID)
		if err != nil {
			fmt.Println("Không thể lấy Public Key chủ sở hữu.")
			return
		}
	}

	sharedSecret, err := crypto.DeriveSharedKey(app.PrivKey, ownerPub)
	if err != nil {
		fmt.Println("Lỗi shared secret.", err)
		return
	}

	aesKey, err := crypto.DecryptAES(myEncKey, sharedSecret)
	if err != nil {
		fmt.Println("Không thể giải mã khóa.", err)
		return
	}

	targetSharedSecret, err := crypto.DeriveSharedKey(app.PrivKey, targetPub)
	if err != nil {
		fmt.Println("Lỗi tạo shared secret với người nhận.", err)
		return
	}

	targetEncKey, err := crypto.EncryptAES(aesKey, targetSharedSecret)
	if err != nil {
		fmt.Println("Không thể mã hóa khóa cho người nhận.", err)
		return
	}

	if err := app.Client.ShareNote(noteID, targetUser, targetEncKey); err != nil {
		fmt.Println("Chia sẻ thất bại:", err)
	} else {
		fmt.Println("Đã chia sẻ ghi chú thành công!")
	}
}

func (app *App) shareViaUrl() {
	prompt := promptui.Prompt{Label: "Note ID"}
	noteID, _ := prompt.Run()

	note, err := app.Client.GetNote(noteID)
	if err != nil {
		fmt.Println("Không thể lấy thông tin ghi chú:", err)
		return
	}

	myEncKey, ok := note.SharedKeys[app.CurrentUser.ID]
	if !ok {
		fmt.Println("Bạn không có quyền truy cập ghi chú này.")
		return
	}

	var ownerPub []byte
	if note.OwnerID == app.CurrentUser.ID {
		ownerPub = app.CurrentUser.PublicKey
	} else {
		ownerPub, err = app.Client.GetUserPublicKey(note.OwnerID)
		if err != nil {
			fmt.Println("Không thể lấy Public Key chủ sở hữu.")
			return
		}
	}

	sharedSecret, err := crypto.DeriveSharedKey(app.PrivKey, ownerPub)
	if err != nil {
		fmt.Println("Lỗi shared secret.", err)
		return
	}

	aesKey, err := crypto.DecryptAES(myEncKey, sharedSecret)
	if err != nil {
		fmt.Println("Không thể giải mã khóa.", err)
		return
	}

	token, err := app.Client.GenerateShareLink(noteID)
	if err != nil {
		fmt.Println("Lỗi tạo link:", err)
		return
	}

	aesKeyHex := hex.EncodeToString(aesKey)
	fullLink := fmt.Sprintf("%s/public/notes/%s#%s", app.Client.BaseURL, token, aesKeyHex)

	fmt.Println("--- LINK CHIA SẺ ---")
	fmt.Println(fullLink)
	fmt.Println("(Gửi link này cho người nhận. Họ có thể tải file mà không cần tài khoản)")
	fmt.Println("--------------------")
}

func (app *App) downloadFromUrl() {
	prompt := promptui.Prompt{Label: "Nhập Link chia sẻ"}
	inputLink, _ := prompt.Run()

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

	note, err := app.Client.GetPublicNote(urlPart)
	if err != nil {
		fmt.Println("Không thể tải ghi chú từ link:", err)
		return
	}

	plaintext, err := crypto.DecryptAES(note.Content, aesKey)
	if err != nil {
		fmt.Printf("Lỗi giải mã nội dung: %v\n", err)
		return
	}

	defaultFilename := note.Filename
	if defaultFilename == "" {
		defaultFilename = "downloaded_via_link.txt"
	}

	filePrompt := promptui.Prompt{
		Label:   "Lưu thành file (Enter để dùng tên gốc)",
		Default: defaultFilename,
	}
	outPath, _ := filePrompt.Run()

	if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
		fmt.Printf("Lỗi lưu file: %v\n", err)
	} else {
		fmt.Printf("\n--- Tải file thành công ---\n")
		fmt.Printf("Tiêu đề: %s\n", note.Title)
		fmt.Printf("Đã lưu tại: %s\n", outPath)
		fmt.Println("---------------------------")
	}
}

func (app *App) deleteNote() {
	prompt := promptui.Prompt{Label: "Note ID cần xóa"}
	id, _ := prompt.Run()

	req, _ := http.NewRequest("DELETE", app.Client.BaseURL+"/notes?id="+id, nil)
	req.Header.Set("Authorization", "Bearer "+app.Client.Token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Lỗi kết nối:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Đã xóa ghi chú thành công!")
	} else {
		fmt.Println("Lỗi xóa ghi chú:", resp.Status)
	}
}
