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
Hệ thống tuân theo mô hình **Client-Server** với thiết kế **Zero-Knowledge** và **Modular Refactoring**.

**Các thành phần chính (Main Components)**:

1.  **Client Application (Ứng dụng nười dùng)**:
    *   **Giao diện (UI)**: Cung cấp menu dòng lệnh (CLI) để người dùng tương tác (Đăng ký, Đăng nhập, Gửi/Nhận file).
    *   **Client API Layer**: Module chịu trách nhiệm đóng gói dữ liệu và gửi các HTTP Request tới Server.
    *   **Client Crypto Module**: Thành phần quan trọng nhất, thực hiện mã hóa AES-256 nội dung file và trao đổi khóa ECDH. Đảm bảo dữ liệu rời khỏi máy người dùng luôn ở dạng mã hóa.

2.  **Server Application (Máy chủ)**:
    *   **Request Handlers**: Tiếp nhận các yêu cầu từ Client, kiểm tra tính hợp lệ của dữ liệu đầu vào.
    *   **Authentication Middleware**: Xác thực người dùng thông qua JWT Token trước khi cho phép truy cập tài nguyên.
    *   **Server Crypto Module**: Chỉ thực hiện các tác vụ của Server như băm mật khẩu (Hashing) và ký Token. Không dính dáng đến khóa giải mã file.
    *   **Storage Layer**: Tương tác trực tiếp với cơ sở dữ liệu SQLite, thực hiện các truy vấn tối ưu hóa (WAL Mode).

3.  **Database (Cơ sở dữ liệu)**:
    *   **SQLite**: Lưu trữ bền vững thông tin người dùng, metadata của ghi chú và các khối dữ liệu (BLOB) đã mã hóa.

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
    - Để chính mình đọc lại được, Client A lấy `PubKey_A`, kết hợp `PrivKey_A` $\rightarrow$ `SharedSecret`.
    - Mã hóa khóa file: $K_{Enc} = AES\_GCM(K_{File}, Hash(SharedSecret))$.
    - Gửi $\{Content_{Enc}, K_{Enc}\}$ lên Server.

3.  **Chia sẻ cho B (Share Note)**:
    - Client A tải `PubKey_B` từ Server.
    - Client A tính `SharedSecret_AB = ECDH(PrivKey_A, PubKey_B)`.
    - Client A giải mã `K_File` (dùng khóa của mình).
    - Client A mã hóa `K_File` bằng `SharedSecret_AB`: $K_{EncB} = AES\_GCM(K_{File}, Hash(SharedSecret_{AB}))$.
    - Gửi `K_{EncB}` lên Server cho B.

### 3.2 Tối ưu hóa (Optimization)
- **SQLite (Pure Go)**: Sử dụng driver không cần CGO (`modernc.org/sqlite`) giúp việc biên dịch và chạy trên Windows dễ dàng hơn.
- **Write-Ahead Logging (WAL)**: Cấu hình `PRAGMA journal_mode=WAL;` giúp tăng hiệu năng xử lý đồng thời, cho phép đọc/ghi song song.
- **Connection Pooling**: Sử dụng DSN parameters (`busy_timeout=5000`) để quản lý timeout kết nối hiệu quả, tránh lỗi "database locked" khi tải cao.
- **Indexing**: Đánh chỉ mục cho các trường `owner_id` và `share_token` để tăng tốc độ truy vấn.

---

## 4. Thách thức và Giải pháp

### 4.1 Chuyển đổi từ RSA sang ECDH
- **Vấn đề**: RSA mã hóa trực tiếp được khóa nhỏ, nhưng ECDH chỉ tạo ra Shared Secret chứ không mã hóa trực tiếp.
- **Giải pháp**: Sử dụng cơ chế **Key Wrapping**. Dùng ECDH để tạo Shared Secret, sau đó Hash(SharedSecret) để làm khóa AES dùng để mã hóa cái "File Key".

### 4.2 Bảo mật Mật khẩu
- **Vấn đề**: SHA-256 thuần túy dễ bị tấn công bởi Rainbow Table.
- **Giải pháp**: Triển khai **Salt**. Mỗi user có một chuỗi Salt ngẫu nhiên 16-byte lưu trong DB. Khi hash, chuỗi này được nối vào password.

### 4.3 Đồng bộ hóa (Concurrency)
- **Vấn đề**: SQLite mặc định lock toàn bộ database khi ghi, gây lỗi khi stress test nhiều user.
- **Giải pháp**: 
    1. Chuyển sang **WAL Mode** (Write-Ahead Logging).
    2. Cấu hình **Busy Timeout** để driver tự động chờ (backoff) thay vì fail ngay.
    3. Kết quả là hệ thống chịu tải tốt (50/50 requests thành công trong bài test stress).

---

## 5. Kiểm thử

### 5.1 Phương pháp
Kết hợp **Automated Testing** (Go test framework) và **Manual Testing** (CLI Client).

#### Automated Testing
- **Framework**: Go testing package (`testing`)
- **Coverage**: **7 test suites, 48+ test cases**
- **Test Architecture**:
  - **Test Isolation**: Mỗi test sử dụng `TestContext` riêng biệt với database tạm và HTTP server độc lập
  - **Auto Cleanup**: Sử dụng `t.TempDir()` để tự động dọn dẹp resources sau mỗi test
  - **Error Handling**: Tất cả errors từ crypto operations và JSON marshaling đều được kiểm tra đầy đủ
- **Test Types**:
  - **Crypto Unit Tests** (MỚI): ECDH key exchange thực tế, AES encryption/decryption, negative test cases
  - **Unit Tests**: Mã hóa AES-GCM, validation
  - **Integration Tests**: API endpoints, database operations
  - **E2E Tests**: Luồng hoàn chỉnh từ đăng ký đến chia sẻ
  - **Concurrent Tests**: Race conditions, stress testing

#### Manual Testing
- Kiểm thử thủ công các kịch bản phức tạp trên CLI Client
- Xác minh file integrity (SHA-256 checksum)
- Test cross-platform compatibility

### 5.2 Kết quả Kiểm thử

#### Automated Test Results
**Tổng quan**: ✅ **PASS 100% (7/7 test suites)**

**Chi tiết**:
1. **Authentication** (8 tests): Đăng ký, Đăng nhập, JWT, Hash Password, Invalid credentials ✅
2. **Encryption** (3 tests): AES-GCM integrity, Key Size validation ✅
3. **Crypto Unit Tests** (8 tests - MỚI): 
    - ECDH Key Exchange (real implementation) ✅
    - ECDH Key Uniqueness ✅
    - Invalid Public Key handling ✅
    - AES Encrypt/Decrypt cycle ✅
    - Decrypt with wrong key (negative test) ✅
    - Encryption uniqueness (nonce randomness) ✅
    - Invalid ciphertext handling ✅
    - Key serialization/deserialization ✅
4. **E2E Encryption** (4 tests): Mã hóa đầu cuối, Shared keys, Multi-user, Key Rotation ✅
5. **Access Control** (8 tests): Phân quyền, Share Link, Expired Link, Revoke, List shared ✅
6. **Integration & Stress** (6 tests): 
    - Full Workflow ✅
    - Concurrent Note Creation ✅
    - **Stress Test**: Multiple users với concurrent operations ✅
    - **Share Link Scenarios**: Expiration và Max Visits ✅
7. **Multi-Share** (1 test): Time-based và visit-based link expiration ✅

#### Manual Test Results
- **Đăng ký/Đăng nhập**: Thành công, tạo file `.pem` local.
- **Mã hóa**: File tải về giải mã trùng khớp hash gốc.
- **Chia sẻ**: User được share giải mã thành công, User khác không truy cập được.

#### Lệnh chạy test
```bash
# Chạy tất cả tests
go test ./test/... -v

# Hoặc dùng script tổng hợp
./test/run_tests.sh
```

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
