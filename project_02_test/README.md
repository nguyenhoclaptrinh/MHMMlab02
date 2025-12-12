# Test Suite - Ứng dụng Chia sẻ Ghi chú Bảo mật

## Tổng quan

Thư mục này chứa các test cases để kiểm thử toàn diện ứng dụng chia sẻ ghi chú bảo mật. Test suite được thiết kế để đáp ứng các yêu cầu kiểm thử trong đề bài.

## Cấu trúc Test

```
test/
├── README.md                   # File này
├── auth_test.go               # Test xác thực người dùng
├── encryption_test.go         # Test mã hóa/giải mã
├── access_control_test.go     # Test giới hạn truy cập
├── e2e_encryption_test.go     # Test mã hóa đầu-cuối
└── testdata/                  # Dữ liệu test (nếu cần)
```

## Danh sách Test Cases

### 1. Xác thực người dùng (auth_test.go)

Test các chức năng đăng ký, đăng nhập và quản lý phiên làm việc:

- ✅ `TestRegisterSuccess` - Đăng ký thành công
- ✅ `TestRegisterDuplicateUsername` - Đăng ký với username đã tồn tại
- ✅ `TestRegisterWeakPassword` - Đăng ký với mật khẩu yếu (nhiều trường hợp)
  - Mật khẩu quá ngắn
  - Thiếu chữ hoa
  - Thiếu chữ thường
  - Thiếu số
  - Thiếu ký tự đặc biệt
- ✅ `TestLoginSuccess` - Đăng nhập thành công
- ✅ `TestLoginInvalidCredentials` - Đăng nhập với thông tin sai
  - Sai mật khẩu
  - Sai username
  - Cả hai sai
- ✅ `TestPasswordHashing` - Kiểm tra mật khẩu được hash đúng cách
- ✅ `TestTokenValidation` - Kiểm tra JWT token hợp lệ

### 2. Mã hóa/Giải mã (encryption_test.go)

Test các chức năng mã hóa client-side:

- ✅ `TestAESEncryptionDecryption` - Mã hóa và giải mã AES cơ bản
- ✅ `TestAESWithDifferentKeys` - Mã hóa với các khóa khác nhau
- ✅ `TestEachNoteHasUniqueKey` - Mỗi ghi chú có khóa riêng
- ✅ `TestAESGCMMode` - Sử dụng AES-GCM mode (authenticated encryption)
- ✅ `TestAESGCMTampering` - GCM phát hiện được dữ liệu bị sửa đổi
- ✅ `TestKeyGeneration` - Tạo khóa ngẫu nhiên an toàn
- ✅ `TestLargeFileEncryption` - Mã hóa file lớn (10 MB)
- ✅ `TestKeyProtection` - Khóa được bảo vệ đúng cách
- ✅ `TestEmptyData` - Xử lý dữ liệu rỗng

### 3. Giới hạn truy cập (access_control_test.go)

Test tính năng URL tạm thời và kiểm soát thời gian:

- ✅ `TestCreateShareLink` - Tạo link chia sẻ thành công
- ✅ `TestAccessValidShareLink` - Truy cập link hợp lệ
- ✅ `TestExpiredShareLink` - Link đã hết hạn không thể truy cập
- ✅ `TestInvalidShareToken` - Token không hợp lệ
- ✅ `TestShareLinkPermissions` - Chỉ owner mới tạo được link
- ✅ `TestMultipleAccessToShareLink` - Có thể truy cập link nhiều lần
- ✅ `TestReuseShareToken` - Share token được tái sử dụng
- ✅ `TestDeleteNoteInvalidatesShareLink` - Xóa note làm vô hiệu link
- ✅ `TestShareLinkWithoutAuthentication` - Truy cập public link không cần đăng nhập
- ✅ `TestExpiryTimeValidation` - Validate thời gian hết hạn

### 4. Mã hóa đầu-cuối (e2e_encryption_test.go)

Test tính năng chia sẻ ghi chú an toàn giữa người dùng:

- ✅ `TestShareNoteToUser` - Chia sẻ ghi chú cho người dùng khác
- ✅ `TestUnauthorizedUserCannotAccess` - User không được share không thể truy cập
- ✅ `TestOnlyOwnerCanShare` - Chỉ owner mới có thể share
- ✅ `TestKeyEncryptionPerUser` - Mỗi user có key được mã hóa riêng
- ✅ `TestRSAKeyPairGeneration` - Tạo cặp khóa RSA
- ✅ `TestEncryptDecryptWithRSA` - Mã hóa/giải mã bằng RSA
- ✅ `TestCannotDecryptWithWrongKey` - Không giải mã được với sai khóa
- ✅ `TestServerNeverSeesPlainKey` - Server không bao giờ thấy plaintext key
- ✅ `TestMultipleUsersAccessSameNote` - Nhiều users truy cập cùng note

## Cách chạy Test

### Yêu cầu

- Go 1.21 trở lên
- Database SQLite hoặc PostgreSQL đã được cấu hình
- Server và client dependencies đã được cài đặt

### Chạy toàn bộ test suite

```bash
cd test
go test -v ./...
```

### Chạy test cho một module cụ thể

```bash
# Test xác thực
go test -v -run TestAuth

# Test mã hóa
go test -v -run TestAES

# Test giới hạn truy cập
go test -v -run TestAccess

# Test E2E encryption
go test -v -run TestShare
```

### Chạy một test case cụ thể

```bash
go test -v -run TestRegisterSuccess
```

### Chạy test với coverage

```bash
go test -v -cover ./...
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Kết quả mong đợi

### Các test phải pass:

1. **Xác thực**: Tất cả test về đăng ký, đăng nhập, validation mật khẩu
2. **Mã hóa**: AES encryption/decryption, key generation, GCM mode
3. **Giới hạn truy cập**: URL tạm thời, kiểm soát thời gian, permissions
4. **E2E Encryption**: Chia sẻ an toàn, RSA key exchange, access control

### Các test có thể skip:

- `TestRevokeAccess` - Tính năng thu hồi quyền chưa implement

## Phương pháp kiểm thử

### Unit Testing
- Test từng function/method độc lập
- Mock dependencies khi cần thiết
- Kiểm tra các edge cases và error handling

### Integration Testing
- Test tương tác giữa các components
- Test với database thật
- Test API endpoints end-to-end

### Security Testing
- Test với mật khẩu yếu
- Test với dữ liệu bị tamper
- Test unauthorized access
- Test key management

## Công cụ/Framework sử dụng

- **Go testing package**: Framework test chuẩn của Go
- **net/http/httptest**: Mock HTTP requests/responses
- **crypto/aes, crypto/rsa**: Test cryptographic functions
- **database/sql**: Test database operations

## Lưu ý quan trọng

### 1. Test Data Cleanup
Mỗi test phải clean up data sau khi chạy xong để tránh ảnh hưởng đến test khác:
```go
defer cleanupTestData()
```

### 2. Test Isolation
Các test phải độc lập, không phụ thuộc vào thứ tự chạy.

### 3. Security Best Practices
- Không hardcode passwords thực trong test
- Không commit sensitive data vào git
- Sử dụng test database riêng

### 4. Performance
- Một số test có thể chậm (TestLargeFileEncryption)
- Có thể skip các test chậm khi develop: `go test -short`

## Các trường hợp lỗi được test

### Xác thực
- Mật khẩu không đủ mạnh
- Username đã tồn tại
- Thông tin đăng nhập sai
- Token không hợp lệ

### Mã hóa
- Sai khóa giải mã
- Dữ liệu bị sửa đổi (tampering)
- Key không được bảo vệ

### Giới hạn truy cập
- URL đã hết hạn
- Token không hợp lệ
- Không có quyền tạo link

### E2E Encryption
- Truy cập trái phép
- Sai private key
- Chia sẻ bởi non-owner

## Cải tiến tương lai

1. **Thêm performance benchmarks**
   ```bash
   go test -bench=.
   ```

2. **Thêm load testing**
   - Test với nhiều concurrent users
   - Test với large datasets

3. **Thêm fuzzing tests**
   ```bash
   go test -fuzz=.
   ```

4. **CI/CD Integration**
   - Tự động chạy tests trên GitHub Actions
   - Code coverage reporting

## Liên hệ

Mọi thắc mắc về test suite vui lòng tham khảo:
- Source code trong từng file test
- Documentation trong comments
- README.md của project chính

---

**Lưu ý**: Đây là test suite mẫu. Một số test functions có thể cần điều chỉnh để phù hợp với implementation cụ thể của bạn. Đặc biệt là các helper functions (`setupTestServer`, `cleanupTestData`, etc.) cần được implement theo cấu trúc thực tế của ứng dụng.
