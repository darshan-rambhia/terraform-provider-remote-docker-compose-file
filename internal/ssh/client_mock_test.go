package ssh

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

// MockGoSFTPClient implements the GoSFTPClientInterface for testing.
type MockGoSFTPClient struct {
	UploadFileFunc  func(ctx context.Context, localPath, remotePath string) error
	GetFileHashFunc func(ctx context.Context, remotePath string) (string, error)
	SetFileAttrFunc func(ctx context.Context, remotePath, owner, group, mode string) error
	DeleteFileFunc  func(ctx context.Context, remotePath string) error
	FileExistsFunc  func(ctx context.Context, remotePath string) (bool, error)
	GetFileInfoFunc func(ctx context.Context, remotePath string) (os.FileInfo, error)
	ReadFileFunc    func(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error)
	CloseFunc       func() error
}

func (m *MockGoSFTPClient) UploadFile(ctx context.Context, localPath, remotePath string) error {
	if m.UploadFileFunc != nil {
		return m.UploadFileFunc(ctx, localPath, remotePath)
	}
	return nil
}

func (m *MockGoSFTPClient) GetFileHash(ctx context.Context, remotePath string) (string, error) {
	if m.GetFileHashFunc != nil {
		return m.GetFileHashFunc(ctx, remotePath)
	}
	return "sha256:abc123", nil
}

func (m *MockGoSFTPClient) SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error {
	if m.SetFileAttrFunc != nil {
		return m.SetFileAttrFunc(ctx, remotePath, owner, group, mode)
	}
	return nil
}

func (m *MockGoSFTPClient) DeleteFile(ctx context.Context, remotePath string) error {
	if m.DeleteFileFunc != nil {
		return m.DeleteFileFunc(ctx, remotePath)
	}
	return nil
}

func (m *MockGoSFTPClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	if m.FileExistsFunc != nil {
		return m.FileExistsFunc(ctx, remotePath)
	}
	return true, nil
}

func (m *MockGoSFTPClient) GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error) {
	if m.GetFileInfoFunc != nil {
		return m.GetFileInfoFunc(ctx, remotePath)
	}
	return nil, nil
}

func (m *MockGoSFTPClient) ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	if m.ReadFileFunc != nil {
		return m.ReadFileFunc(ctx, remotePath, maxBytes)
	}
	return []byte("file content"), nil
}

func (m *MockGoSFTPClient) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// MockFileInfo implements os.FileInfo for testing.
type MockFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func (m *MockFileInfo) Name() string       { return m.name }
func (m *MockFileInfo) Size() int64        { return m.size }
func (m *MockFileInfo) Mode() fs.FileMode  { return m.mode }
func (m *MockFileInfo) ModTime() time.Time { return m.modTime }
func (m *MockFileInfo) IsDir() bool        { return m.isDir }
func (m *MockFileInfo) Sys() interface{}   { return nil }

// Test Client Close.
func TestClient_Close(t *testing.T) {
	client := &Client{
		gosftpClient: &MockGoSFTPClient{
			CloseFunc: func() error { return nil },
		},
		config: Config{Host: "example.com"},
	}

	err := client.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestClient_Close_Error(t *testing.T) {
	expectedErr := errors.New("close failed")
	client := &Client{
		gosftpClient: &MockGoSFTPClient{
			CloseFunc: func() error { return expectedErr },
		},
		config: Config{Host: "example.com"},
	}

	err := client.Close()
	if err != expectedErr {
		t.Errorf("Close() error = %v, want %v", err, expectedErr)
	}
}

// Test UploadContent.
func TestClient_UploadContent_Success(t *testing.T) {
	uploadCalled := false
	mockClient := &MockGoSFTPClient{
		UploadFileFunc: func(ctx context.Context, localPath, remotePath string) error {
			uploadCalled = true
			if remotePath != "/tmp/test.txt" {
				t.Errorf("UploadFile got remotePath = %v, want '/tmp/test.txt'", remotePath)
			}
			return nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.UploadContent(context.Background(), []byte("test content"), "/tmp/test.txt")
	if err != nil {
		t.Errorf("UploadContent() error = %v, want nil", err)
	}
	if !uploadCalled {
		t.Error("UploadFile was not called")
	}
}

func TestClient_UploadContent_Error(t *testing.T) {
	expectedErr := errors.New("upload failed")
	mockClient := &MockGoSFTPClient{
		UploadFileFunc: func(ctx context.Context, localPath, remotePath string) error {
			return expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.UploadContent(context.Background(), []byte("test"), "/tmp/test.txt")
	if err != expectedErr {
		t.Errorf("UploadContent() error = %v, want %v", err, expectedErr)
	}
}

// Test UploadFile.
func TestClient_UploadFile_Success(t *testing.T) {
	mockClient := &MockGoSFTPClient{
		UploadFileFunc: func(ctx context.Context, localPath, remotePath string) error {
			if localPath != "/local/test.txt" {
				t.Errorf("UploadFile got localPath = %v, want '/local/test.txt'", localPath)
			}
			if remotePath != "/remote/test.txt" {
				t.Errorf("UploadFile got remotePath = %v, want '/remote/test.txt'", remotePath)
			}
			return nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.UploadFile(context.Background(), "/local/test.txt", "/remote/test.txt")
	if err != nil {
		t.Errorf("UploadFile() error = %v, want nil", err)
	}
}

// Test GetFileHash.
func TestClient_GetFileHash_Success(t *testing.T) {
	expectedHash := "sha256:abc123def456"
	mockClient := &MockGoSFTPClient{
		GetFileHashFunc: func(ctx context.Context, remotePath string) (string, error) {
			if remotePath != "/tmp/test.txt" {
				t.Errorf("GetFileHash got remotePath = %v, want '/tmp/test.txt'", remotePath)
			}
			return expectedHash, nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	hash, err := client.GetFileHash(context.Background(), "/tmp/test.txt")
	if err != nil {
		t.Errorf("GetFileHash() error = %v, want nil", err)
	}
	if hash != expectedHash {
		t.Errorf("GetFileHash() = %v, want %v", hash, expectedHash)
	}
}

func TestClient_GetFileHash_Error(t *testing.T) {
	expectedErr := errors.New("hash failed")
	mockClient := &MockGoSFTPClient{
		GetFileHashFunc: func(ctx context.Context, remotePath string) (string, error) {
			return "", expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	_, err := client.GetFileHash(context.Background(), "/tmp/test.txt")
	if err != expectedErr {
		t.Errorf("GetFileHash() error = %v, want %v", err, expectedErr)
	}
}

// Test FileExists.
func TestClient_FileExists_Exists(t *testing.T) {
	mockClient := &MockGoSFTPClient{
		FileExistsFunc: func(ctx context.Context, remotePath string) (bool, error) {
			return true, nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	exists, err := client.FileExists(context.Background(), "/tmp/test.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v, want nil", err)
	}
	if !exists {
		t.Errorf("FileExists() = %v, want true", exists)
	}
}

func TestClient_FileExists_NotFound(t *testing.T) {
	mockClient := &MockGoSFTPClient{
		FileExistsFunc: func(ctx context.Context, remotePath string) (bool, error) {
			return false, nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	exists, err := client.FileExists(context.Background(), "/tmp/test.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v, want nil", err)
	}
	if exists {
		t.Errorf("FileExists() = %v, want false", exists)
	}
}

// Test DeleteFile.
func TestClient_DeleteFile_Success(t *testing.T) {
	deleteCalled := false
	mockClient := &MockGoSFTPClient{
		DeleteFileFunc: func(ctx context.Context, remotePath string) error {
			deleteCalled = true
			if remotePath != "/tmp/test.txt" {
				t.Errorf("DeleteFile got remotePath = %v", remotePath)
			}
			return nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.DeleteFile(context.Background(), "/tmp/test.txt")
	if err != nil {
		t.Errorf("DeleteFile() error = %v, want nil", err)
	}
	if !deleteCalled {
		t.Error("DeleteFile() was not called")
	}
}

func TestClient_DeleteFile_Error(t *testing.T) {
	expectedErr := errors.New("delete failed")
	mockClient := &MockGoSFTPClient{
		DeleteFileFunc: func(ctx context.Context, remotePath string) error {
			return expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.DeleteFile(context.Background(), "/tmp/test.txt")
	if err != expectedErr {
		t.Errorf("DeleteFile() error = %v, want %v", err, expectedErr)
	}
}

// Test ReadFileContent.
func TestClient_ReadFileContent_Success(t *testing.T) {
	expectedContent := []byte("file content")
	mockClient := &MockGoSFTPClient{
		ReadFileFunc: func(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
			if remotePath != "/tmp/test.txt" {
				t.Errorf("ReadFileContent got remotePath = %v, want '/tmp/test.txt'", remotePath)
			}
			if maxBytes != 1024 {
				t.Errorf("ReadFileContent got maxBytes = %v, want 1024", maxBytes)
			}
			return expectedContent, nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	content, err := client.ReadFileContent(context.Background(), "/tmp/test.txt", 1024)
	if err != nil {
		t.Errorf("ReadFileContent() error = %v, want nil", err)
	}
	if string(content) != string(expectedContent) {
		t.Errorf("ReadFileContent() = %v, want %v", content, expectedContent)
	}
}

// Test GetFileInfo.
func TestClient_GetFileInfo_Success(t *testing.T) {
	mockFileInfo := &MockFileInfo{
		name:    "test.txt",
		size:    1024,
		isDir:   false,
		modTime: time.Now(),
	}
	mockClient := &MockGoSFTPClient{
		GetFileInfoFunc: func(ctx context.Context, remotePath string) (os.FileInfo, error) {
			return mockFileInfo, nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	info, err := client.GetFileInfo(context.Background(), "/tmp/test.txt")
	if err != nil {
		t.Errorf("GetFileInfo() error = %v, want nil", err)
	}
	if info.Name() != "test.txt" {
		t.Errorf("GetFileInfo() Name = %v, want 'test.txt'", info.Name())
	}
	if info.Size() != 1024 {
		t.Errorf("GetFileInfo() Size = %v, want 1024", info.Size())
	}
}

// Test SetFileAttributes.
func TestClient_SetFileAttributes_Success(t *testing.T) {
	mockClient := &MockGoSFTPClient{
		SetFileAttrFunc: func(ctx context.Context, remotePath, owner, group, mode string) error {
			if remotePath != "/tmp/test.txt" {
				t.Errorf("SetFileAttributes got remotePath = %v", remotePath)
			}
			if owner != "root" {
				t.Errorf("SetFileAttributes got owner = %v, want 'root'", owner)
			}
			if group != "root" {
				t.Errorf("SetFileAttributes got group = %v, want 'root'", group)
			}
			if mode != "0644" {
				t.Errorf("SetFileAttributes got mode = %v, want '0644'", mode)
			}
			return nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.SetFileAttributes(context.Background(), "/tmp/test.txt", "root", "root", "0644")
	if err != nil {
		t.Errorf("SetFileAttributes() error = %v, want nil", err)
	}
}

func TestClient_SetFileAttributes_Error(t *testing.T) {
	expectedErr := errors.New("chmod failed")
	mockClient := &MockGoSFTPClient{
		SetFileAttrFunc: func(ctx context.Context, remotePath, owner, group, mode string) error {
			return expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.SetFileAttributes(context.Background(), "/tmp/test.txt", "root", "root", "0644")
	if err != expectedErr {
		t.Errorf("SetFileAttributes() error = %v, want %v", err, expectedErr)
	}
}

// Test SetFileAttributes validation.
func TestClient_SetFileAttributes_InvalidOwner(t *testing.T) {
	client := &Client{
		gosftpClient: &MockGoSFTPClient{},
		config:       Config{Host: "example.com"},
	}

	err := client.SetFileAttributes(context.Background(), "/tmp/test.txt", "invalid user", "root", "0644")
	if err == nil {
		t.Errorf("SetFileAttributes() error = nil, want validation error")
	}
}

func TestClient_SetFileAttributes_InvalidMode(t *testing.T) {
	client := &Client{
		gosftpClient: &MockGoSFTPClient{},
		config:       Config{Host: "example.com"},
	}

	err := client.SetFileAttributes(context.Background(), "/tmp/test.txt", "root", "root", "invalid")
	if err == nil {
		t.Errorf("SetFileAttributes() error = nil, want validation error")
	}
}

// Test buildAuthMethods.
func TestBuildAuthMethods_Password(t *testing.T) {
	config := Config{
		Password: "testpass",
	}

	authMethods, err := buildAuthMethods(config)
	if err != nil {
		t.Errorf("buildAuthMethods() error = %v, want nil", err)
	}
	if len(authMethods) == 0 {
		t.Errorf("buildAuthMethods() returned 0 auth methods, want at least 1")
	}
}

func TestBuildAuthMethods_PasswordMissing(t *testing.T) {
	config := Config{
		AuthMethod: AuthMethodPassword,
	}

	authMethods, err := buildAuthMethods(config)
	if err == nil {
		t.Errorf("buildAuthMethods() error = nil, want error for missing password")
	}
	if authMethods != nil {
		t.Errorf("buildAuthMethods() returned authMethods, want nil")
	}
}

func TestBuildAuthMethods_PrivateKeyMissing(t *testing.T) {
	config := Config{
		AuthMethod: AuthMethodPrivateKey,
	}

	authMethods, err := buildAuthMethods(config)
	if err == nil {
		t.Errorf("buildAuthMethods() error = nil, want error for missing private key")
	}
	if authMethods != nil {
		t.Errorf("buildAuthMethods() returned authMethods, want nil")
	}
}

func TestBuildAuthMethods_CertificateMissing(t *testing.T) {
	config := Config{
		AuthMethod: AuthMethodCertificate,
	}

	authMethods, err := buildAuthMethods(config)
	if err == nil {
		t.Errorf("buildAuthMethods() error = nil, want error for missing certificate")
	}
	if authMethods != nil {
		t.Errorf("buildAuthMethods() returned authMethods, want nil")
	}
}

// Test inferAuthMethod.
func TestInferAuthMethod_Password(t *testing.T) {
	config := Config{
		Password: "testpass",
	}

	method := inferAuthMethod(config)
	if method != AuthMethodPassword {
		t.Errorf("inferAuthMethod() = %v, want %v", method, AuthMethodPassword)
	}
}

func TestInferAuthMethod_Certificate(t *testing.T) {
	config := Config{
		Certificate: "cert-data",
	}

	method := inferAuthMethod(config)
	if method != AuthMethodCertificate {
		t.Errorf("inferAuthMethod() = %v, want %v", method, AuthMethodCertificate)
	}
}

func TestInferAuthMethod_DefaultPrivateKey(t *testing.T) {
	config := Config{}

	method := inferAuthMethod(config)
	if method != AuthMethodPrivateKey {
		t.Errorf("inferAuthMethod() = %v, want %v", method, AuthMethodPrivateKey)
	}
}

// Test buildPrivateKeyAuth.
func TestBuildPrivateKeyAuth_NoKeyProvided(t *testing.T) {
	config := Config{}

	authMethod, err := buildPrivateKeyAuth(config)
	if err == nil {
		t.Errorf("buildPrivateKeyAuth() error = nil, want error for missing key")
	}
	if authMethod != nil {
		t.Errorf("buildPrivateKeyAuth() returned authMethod, want nil")
	}
}

func TestBuildPrivateKeyAuth_InvalidKeyData(t *testing.T) {
	config := Config{
		PrivateKey: "invalid-key-data",
	}

	authMethod, err := buildPrivateKeyAuth(config)
	if err == nil {
		t.Errorf("buildPrivateKeyAuth() error = nil, want error for invalid key")
	}
	if authMethod != nil {
		t.Errorf("buildPrivateKeyAuth() returned authMethod, want nil")
	}
}

// Test buildCertificateAuth.
func TestBuildCertificateAuth_NoCertificateProvided(t *testing.T) {
	config := Config{
		PrivateKey: "test-key",
	}

	authMethod, err := buildCertificateAuth(config)
	if err == nil {
		t.Errorf("buildCertificateAuth() error = nil, want error for missing certificate")
	}
	if authMethod != nil {
		t.Errorf("buildCertificateAuth() returned authMethod, want nil")
	}
}

func TestBuildCertificateAuth_NoPrivateKeyProvided(t *testing.T) {
	config := Config{
		Certificate: "test-cert",
	}

	authMethod, err := buildCertificateAuth(config)
	if err == nil {
		t.Errorf("buildCertificateAuth() error = nil, want error for missing private key")
	}
	if authMethod != nil {
		t.Errorf("buildCertificateAuth() returned authMethod, want nil")
	}
}

func TestBuildCertificateAuth_InvalidPrivateKey(t *testing.T) {
	config := Config{
		PrivateKey:  "invalid-key-data",
		Certificate: "invalid-cert-data",
	}

	authMethod, err := buildCertificateAuth(config)
	if err == nil {
		t.Errorf("buildCertificateAuth() error = nil, want error for invalid key/cert")
	}
	if authMethod != nil {
		t.Errorf("buildCertificateAuth() returned authMethod, want nil")
	}
}

// Test buildHostKeyCallback.
func TestBuildHostKeyCallback_InsecureIgnoreHostKey(t *testing.T) {
	config := Config{
		InsecureIgnoreHostKey: true,
	}

	callback, err := buildHostKeyCallback(config)
	if err != nil {
		t.Errorf("buildHostKeyCallback() error = %v, want nil", err)
	}
	if callback == nil {
		t.Errorf("buildHostKeyCallback() returned nil, want HostKeyCallback")
	}
}

func TestBuildHostKeyCallback_InvalidKnownHostsFile(t *testing.T) {
	config := Config{
		InsecureIgnoreHostKey: false,
		KnownHostsFile:        "/nonexistent/path/known_hosts",
	}

	callback, err := buildHostKeyCallback(config)
	if err == nil {
		t.Errorf("buildHostKeyCallback() error = nil, want error for invalid known_hosts path")
	}
	if callback != nil {
		t.Errorf("buildHostKeyCallback() returned callback, want nil")
	}
}

// Test ExpandPath.
func TestExpandPath_RelativePath(t *testing.T) {
	path := "/tmp/test"
	result := ExpandPath(path)
	if result != path {
		t.Errorf("ExpandPath() = %v, want %v", result, path)
	}
}

func TestExpandPath_TildePath(t *testing.T) {
	path := "~/test"
	result := ExpandPath(path)
	if result == path {
		t.Errorf("ExpandPath() = %v, should be expanded", result)
	}
	if !strings.Contains(result, "test") {
		t.Errorf("ExpandPath() = %v, should contain 'test'", result)
	}
}

// Test ValidateMode.
func TestValidateMode_Valid(t *testing.T) {
	validModes := []string{"0644", "0755", "0777", "0600"}
	for _, mode := range validModes {
		err := ValidateMode(mode)
		if err != nil {
			t.Errorf("ValidateMode(%s) error = %v, want nil", mode, err)
		}
	}
}

func TestValidateMode_Invalid(t *testing.T) {
	invalidModes := []string{"invalid", "999", "08", "0999"}
	for _, mode := range invalidModes {
		err := ValidateMode(mode)
		if err == nil {
			t.Errorf("ValidateMode(%s) error = nil, want error", mode)
		}
	}
}

// Test validateOwnerGroup.
func TestValidateOwnerGroup_Valid(t *testing.T) {
	validNames := []string{"root", "user123", "_testuser", "group-name", "1000"}
	for _, name := range validNames {
		err := validateOwnerGroup(name, "test_field")
		if err != nil {
			t.Errorf("validateOwnerGroup(%s) error = %v, want nil", name, err)
		}
	}
}

func TestValidateOwnerGroup_Invalid(t *testing.T) {
	invalidNames := []string{"-invalid", "123-", "user name", ""}
	for _, name := range invalidNames {
		if name == "" {
			// Empty name is valid (means don't change)
			err := validateOwnerGroup(name, "test_field")
			if err != nil {
				t.Errorf("validateOwnerGroup(empty) error = %v, want nil", err)
			}
		} else {
			err := validateOwnerGroup(name, "test_field")
			if err == nil {
				t.Errorf("validateOwnerGroup(%s) error = nil, want error", name)
			}
		}
	}
}

func TestValidateOwnerGroup_TooLong(t *testing.T) {
	longName := strings.Repeat("a", 33)
	err := validateOwnerGroup(longName, "test_field")
	if err == nil {
		t.Errorf("validateOwnerGroup(long name) error = nil, want error")
	}
}

// Test IsBinaryContent.
func TestIsBinaryContent_Binary(t *testing.T) {
	content := []byte{0xFF, 0x00, 0xFF, 0xE0} // Binary content with null byte
	result := IsBinaryContent(content)
	if !result {
		t.Errorf("IsBinaryContent(binary) = false, want true")
	}
}

func TestIsBinaryContent_Text(t *testing.T) {
	content := []byte("Hello, World!")
	result := IsBinaryContent(content)
	if result {
		t.Errorf("IsBinaryContent(text) = true, want false")
	}
}

func TestIsBinaryContent_Empty(t *testing.T) {
	content := []byte{}
	result := IsBinaryContent(content)
	if result {
		t.Errorf("IsBinaryContent(empty) = true, want false")
	}
}

// Test Close with nil client.
func TestClient_Close_NilGosftpClient(t *testing.T) {
	client := &Client{
		gosftpClient: nil,
		config:       Config{Host: "example.com"},
	}

	err := client.Close()
	if err != nil {
		t.Errorf("Close() with nil gosftpClient error = %v, want nil", err)
	}
}

// Test UploadContent with context.
func TestClient_UploadContent_WithContext(t *testing.T) {
	mockClient := &MockGoSFTPClient{
		UploadFileFunc: func(ctx context.Context, localPath, remotePath string) error {
			return nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := client.UploadContent(ctx, []byte("test content"), "/tmp/test.txt")
	if err != nil {
		t.Errorf("UploadContent() error = %v, want nil", err)
	}
}

// Test buildAuthMethods with inferred method.
func TestBuildAuthMethods_InferPassword(t *testing.T) {
	config := Config{
		Password: "testpass",
		// AuthMethod not set, should infer
	}

	authMethods, err := buildAuthMethods(config)
	if err != nil {
		t.Errorf("buildAuthMethods() error = %v, want nil", err)
	}
	if len(authMethods) == 0 {
		t.Errorf("buildAuthMethods() returned 0 auth methods, want at least 1")
	}
}

// Test SetFileAttributes with validation edge case.
func TestClient_SetFileAttributes_EmptyFields(t *testing.T) {
	mockClient := &MockGoSFTPClient{
		SetFileAttrFunc: func(ctx context.Context, remotePath, owner, group, mode string) error {
			return nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	// Empty owner and group should be allowed (means don't change)
	err := client.SetFileAttributes(context.Background(), "/tmp/test.txt", "", "", "0644")
	if err != nil {
		t.Errorf("SetFileAttributes() with empty owner/group error = %v, want nil", err)
	}
}

// Test GetFileHash with context.
func TestClient_GetFileHash_WithContext(t *testing.T) {
	expectedHash := "sha256:abc123"
	mockClient := &MockGoSFTPClient{
		GetFileHashFunc: func(ctx context.Context, remotePath string) (string, error) {
			return expectedHash, nil
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hash, err := client.GetFileHash(ctx, "/tmp/test.txt")
	if err != nil {
		t.Errorf("GetFileHash() error = %v, want nil", err)
	}
	if hash != expectedHash {
		t.Errorf("GetFileHash() = %q, want %q", hash, expectedHash)
	}
}

// Test DeleteFile with error.
func TestClient_DeleteFile_WithError(t *testing.T) {
	expectedErr := errors.New("permission denied")
	mockClient := &MockGoSFTPClient{
		DeleteFileFunc: func(ctx context.Context, remotePath string) error {
			return expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	err := client.DeleteFile(context.Background(), "/tmp/protected.txt")
	if err != expectedErr {
		t.Errorf("DeleteFile() error = %v, want %v", err, expectedErr)
	}
}

// Test FileExists with error.
func TestClient_FileExists_WithError(t *testing.T) {
	expectedErr := errors.New("connection timeout")
	mockClient := &MockGoSFTPClient{
		FileExistsFunc: func(ctx context.Context, remotePath string) (bool, error) {
			return false, expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	exists, err := client.FileExists(context.Background(), "/tmp/test.txt")
	if err != expectedErr {
		t.Errorf("FileExists() error = %v, want %v", err, expectedErr)
	}
	if exists {
		t.Errorf("FileExists() returned true, want false")
	}
}

// Test ReadFileContent with error.
func TestClient_ReadFileContent_WithError(t *testing.T) {
	expectedErr := errors.New("file not found")
	mockClient := &MockGoSFTPClient{
		ReadFileFunc: func(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
			return nil, expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	content, err := client.ReadFileContent(context.Background(), "/tmp/missing.txt", 1024)
	if err != expectedErr {
		t.Errorf("ReadFileContent() error = %v, want %v", err, expectedErr)
	}
	if content != nil {
		t.Errorf("ReadFileContent() returned content, want nil")
	}
}

// Test GetFileInfo with error.
func TestClient_GetFileInfo_WithError(t *testing.T) {
	expectedErr := errors.New("stat failed")
	mockClient := &MockGoSFTPClient{
		GetFileInfoFunc: func(ctx context.Context, remotePath string) (os.FileInfo, error) {
			return nil, expectedErr
		},
	}

	client := &Client{
		gosftpClient: mockClient,
		config:       Config{Host: "example.com"},
	}

	info, err := client.GetFileInfo(context.Background(), "/tmp/test.txt")
	if err != expectedErr {
		t.Errorf("GetFileInfo() error = %v, want %v", err, expectedErr)
	}
	if info != nil {
		t.Errorf("GetFileInfo() returned info, want nil")
	}
}

// Test ValidateMode empty string case.
func TestValidateMode_EmptyIsValid(t *testing.T) {
	err := ValidateMode("")
	if err != nil {
		t.Errorf("ValidateMode(empty) error = %v, want nil", err)
	}
}
