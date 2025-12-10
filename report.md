# Ứng Dụng Chia Sẻ Ghi Chú Bảo Mật - Báo Cáo Dự Án

## 1. Tổng quan ứng dụng

### 1.1 Mục tiêu
Xây dựng một nền tảng chia sẻ ghi chú an toàn, đảm bảo tính riêng tư của dữ liệu thông qua cơ chế mã hóa phía client (Client-side Encryption). Máy chủ đóng vai trò lưu trữ "mù" (blind storage), không thể đọc được nội dung thực tế của ghi chú.

### 1.2 Chức năng đã triển khai
- **Xác thực an toàn**: Đăng ký/Đăng nhập với mật khẩu được bảo vệ bởi Salt và SHA-256. Quản lý phiên bằng JWT (JSON Web Token).
- **Mã hóa đầu-cuối (E2EE)**:
    - Mỗi file được mã hóa bằng một khóa AES ngẫu nhiên riêng biệt.
    - Khóa AES được bảo vệ bằng cơ chế trao đổi khóa Diffie-Hellman (ECDH X25519).
- **Chia sẻ linh hoạt**:
    - Chia sẻ cho người dùng cụ thể trong hệ thống.
    - Chia sẻ công khai qua Link (sử dụng Token và Fragment URL để bảo mật khóa).
- **Quản lý ghi chú**:
    - Upload/Download file mã hóa.
    - Xóa ghi chú (Chủ sở hữu).
    - Tự động kiểm tra thời gian hết hạn (Expiration).

---

## 2. Thiết kế và Kiến trúc

### 2.1 Kiến trúc hệ thống
Hệ thống tuân theo mô hình **Client-Server** truyền thống nhưng với thiết kế "Zero-Knowledge" về mặt dữ liệu nội dung từ phía Server.

**Sơ đồ luồng hoạt động**:
1.  **Client**: Chịu trách nhiệm tạo khóa, mã hóa dữ liệu, gửi dữ liệu đã mã hóa lên Crypto Layer.
2.  **Server**: Chỉ lưu trữ BLOB (Binary Large Object) đã mã hóa và Metadata (ID, Owner, Permissions).
3.  **Database (SQLite)**: Lưu trữ bền vững dữ liệu User và Note.

### 2.2 Công nghệ & Thư viện sử dụng
- **Ngôn ngữ**: Go (Golang) phiên bản 1.22+.
- **Cơ sở dữ liệu**: SQLite (thư viện `modernc.org/sqlite` v1.33.1 - Pure Go driver).
- **Xác thực**:
    - **JWT**: `github.com/golang-jwt/jwt/v5` để tạo và xác thực token Bearer.
    - **Password Hashing**: SHA-256 kết hợp với **Salt** (16 bytes random hex) tự xây dựng.
- **Mật mã học (Cryptography)**:
    - **AES-GCM (256-bit)**: Dùng để mã hóa nội dung file (Thư viện chuẩn `crypto/aes`, `crypto/cipher`).
    - **ECDH (Curve25519/X25519)**: Trao đổi khóa an toàn (Thư viện chuẩn `crypto/ecdh`).
    - **KDF**: SHA-256 để dẫn xuất khóa từ Shared Secret (Thư viện chuẩn `crypto/sha256`).
    - **Random**: `crypto/rand` (CSPRNG) để tạo Salt, IV, và Key.

---

## 3. Chi tiết Cài đặt & Kỹ thuật

### 3.1 Quy trình Mã hóa & Chia sẻ (ECDH + AES)
Đây là phần cốt lõi của ứng dụng.

1.  **Tạo khóa (Registration)**:
    - Client tạo cặp khóa ECDH X25519 (`PrivKey_A`, `PubKey_A`).
    - Gửi `PubKey_A` lên Server lưu trữ. `PrivKey_A` lưu bí mật tại file local (`username.pem`).

2.  **Upload & Mã hóa (Create Note)**:
    - Tạo khóa ngẫu nhiên `K_File` (32 bytes).
    - Mã hóa File: $Content_{Enc} = AES\_GCM(File, K_{File})$.
    - Để chính mình đọc lại được, Client A lấy `PubKey_A` (của chính mình), kết hợp `PrivKey_A` $\rightarrow$ `SharedSecret` (thực ra là ECDH với chính mình hoặc derived key).
    - Mã hóa khóa file: $K_{Enc} = AES\_GCM(K_{File}, Hash(SharedSecret))$.
    - Gửi $\{Content_{Enc}, K_{Enc}\}$ lên Server.

3.  **Chia sẻ cho B (Share Note)**:
    - Client A tải `PubKey_B` từ Server.
    - Client A tính `SharedSecret_AB = ECDH(PrivKey_A, PubKey_B)`.
    - Client A giải mã `K_File` (dùng khóa của mình).
    - Client A mã hóa `K_File` bằng `SharedSecret_AB`: $K_{EncB} = AES\_GCM(K_{File}, Hash(SharedSecret_{AB}))$.
    - Gửi `K_{EncB}` lên Server cho B.

### 3.2 Tối ưu hóa (Optimization)
- **SQLite (Pure Go)**: Sử dụng driver không cần CGO (`modernc.org/sqlite`) giúp việc biên dịch và chạy trên Windows dễ dàng hơn, không cần cài GCC.
- **JWT Caching**: Server xác thực Stateless, không cần query DB để check session ID mỗi lần req (tuy nhiên vẫn check user existence).

---

## 4. Thách thức và Giải pháp

### 4.1 Chuyển đổi từ RSA sang ECDH
- **Vấn đề**: RSA mã hóa trực tiếp được khóa nhỏ, nhưng ECDH chỉ tạo ra Shared Secret chứ không mã hóa trực tiếp.
- **Giải pháp**: Sử dụng cơ chế **Key Wrapping**. Dùng ECDH để tạo Shared Secret, sau đó Hash(SharedSecret) để làm khóa AES dùng để mã hóa cái "File Key". Đây là mô hình Hybrid Encryption chuẩn.

### 4.2 Bảo mật Mật khẩu
- **Vấn đề**: SHA-256 thuần túy dễ bị tấn công bởi Rainbow Table.
- **Giải pháp**: Triển khai **Salt**. Mỗi user có một chuỗi Salt ngẫu nhiên 16-byte lưu trong DB. Khi hash, chuỗi này được nối vào password.

### 4.3 Đồng bộ hóa (Concurrency)
- **Vấn đề**: Ghi đồng thời vào map (phiên bản cũ) gây panic.
- **Giải pháp**: Chuyển sang SQLite với transaction (`db.Begin()`, `tx.Commit()`) đảm bảo tính toàn vẹn dữ liệu (ACID) và thread-safety.

---

## 5. Kiểm thử

### 5.1 Phương pháp
Kiểm thử thủ công (Manual Testing) thông qua kịch bản sử dụng thực tế trên CLI Client.

### 5.2 Kết quả Kiểm thử
1.  **Đăng ký/Đăng nhập**:
    - Thành công tạo User mới, file `.pem` được lưu.
    - Đăng nhập sai pass/username trả về lỗi 401.
    - Đăng nhập đúng trả về JWT Token.
2.  **Mã hóa/Giải mã**:
    - Upload file text/binary, tải về giải mã trùng khớp SHA-256 với file gốc.
    - Không có Private Key (`.pem`) không thể giải mã.
3.  **Chia sẻ (ECDH)**:
    - User A chia sẻ cho User B. User B đăng nhập, tải file và giải mã thành công.
    - User C (không được share) truy cập bị lỗi 403.
4.  **Chia sẻ Link**:
    - Tạo link, mở trên client khác (chọn menu 3) tải thành công mà không cần login.

---

## 6. Hướng dẫn sử dụng

### 6.1 Cài đặt
Yêu cầu: Go 1.22+.
1.  Xóa `server.db` và các file `*.pem` cũ (nếu có).
2.  Chạy Server:
    ```bash
    go run ./cmd/server/main.go
    ```
3.  Chạy Client:
    ```bash
    go run ./cmd/client/main.go
    ```

### 6.2 Các bước cơ bản
1.  **Đăng ký** tài khoản mới.
2.  **Đăng nhập**.
3.  **Tạo ghi chú**: Nhập đường dẫn file (VD: `test.txt`).
4.  **Chia sẻ**: Chọn ID ghi chú và tên người nhận.
5.  **Tải từ Link**: Chọn chức năng "Tải từ Link" và dán URL vào.
