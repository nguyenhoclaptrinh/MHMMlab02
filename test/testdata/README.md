# Test Data Samples

Thư mục này chứa các file dữ liệu mẫu để sử dụng trong test cases.

## Các file có sẵn:

### sample_note.txt
File văn bản đơn giản để test upload/download ghi chú.

### sample_image.png (placeholder)
File ảnh mẫu để test với binary data.

### sample_document.pdf (placeholder)
File PDF mẫu để test với file lớn hơn.

## Sử dụng trong test:

```go
// Đọc file test data
data, err := os.ReadFile("testdata/sample_note.txt")
if err != nil {
    t.Fatal(err)
}

// Sử dụng data trong test
// ...
```

## Lưu ý:
- Không commit file nhạy cảm hoặc file quá lớn vào Git
- Các file ở đây chỉ để test, không phải dữ liệu thực
