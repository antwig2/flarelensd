package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/antwig2/flarelens/internal/config"
)

func TestSigV4Signing(t *testing.T) {
	client := NewR2Client("https://account.r2.cloudflarestorage.com", "test-key-id", "test-secret-key")

	req, err := http.NewRequestWithContext(context.Background(), "PUT", "https://account.r2.cloudflarestorage.com/my-bucket/backup.sql.gz", strings.NewReader("dummy-data"))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	client.signRequest(req, "UNSIGNED-PAYLOAD")

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatalf("Authorization header missing after signing")
	}

	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		t.Errorf("Expected AWS4-HMAC-SHA256 signature prefix, got: %s", auth)
	}

	if !strings.Contains(auth, "Credential=test-key-id/") {
		t.Errorf("Expected test-key-id in credential scope, got: %s", auth)
	}

	if req.Header.Get("x-amz-date") == "" {
		t.Errorf("Expected x-amz-date header to be set")
	}
	if req.Header.Get("x-amz-content-sha256") != "UNSIGNED-PAYLOAD" {
		t.Errorf("Expected x-amz-content-sha256 to be UNSIGNED-PAYLOAD")
	}
}

func TestR2PutAndGetObject(t *testing.T) {
	uploadedData := make(map[string][]byte)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		key := strings.TrimPrefix(r.URL.Path, "/")
		switch r.Method {
		case "PUT":
			data, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			uploadedData[key] = data
			w.WriteHeader(http.StatusOK)
		case "GET":
			data, exists := uploadedData[key]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client := NewR2Client(server.URL, "key", "secret")
	ctx := context.Background()

	testPayload := []byte("SQL DUMP CONTENT: CREATE TABLE users (id serial primary key);")

	// 1. PutObject
	err := client.PutObject(ctx, "flarelens-backups", "postgres/test.sql.gz", bytes.NewReader(testPayload), int64(len(testPayload)), "application/gzip")
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Verify server received payload
	stored, ok := uploadedData["flarelens-backups/postgres/test.sql.gz"]
	if !ok || string(stored) != string(testPayload) {
		t.Fatalf("Server data mismatch, got: %s", string(stored))
	}

	// 2. GetObject
	reader, err := client.GetObject(ctx, "flarelens-backups", "postgres/test.sql.gz")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer reader.Close()

	downloaded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed reading object body: %v", err)
	}

	if string(downloaded) != string(testPayload) {
		t.Errorf("Downloaded content mismatch. Expected %s, got %s", string(testPayload), string(downloaded))
	}
}

func TestR2ListObjects(t *testing.T) {
	mockXML := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>flarelens-backups</Name>
    <Prefix>postgres/</Prefix>
    <Contents>
        <Key>postgres/20261014-020000_daily.sql.gz</Key>
        <LastModified>2026-10-14T02:00:00.000Z</LastModified>
        <Size>1048576</Size>
    </Contents>
    <Contents>
        <Key>postgres/20261014-040000_pre-deploy.sql.gz</Key>
        <LastModified>2026-10-14T04:00:00.000Z</LastModified>
        <Size>2097152</Size>
    </Contents>
</ListBucketResult>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockXML))
	}))
	defer server.Close()

	client := NewR2Client(server.URL, "key", "secret")
	ctx := context.Background()

	objs, err := client.ListObjects(ctx, "flarelens-backups", "postgres/")
	if err != nil {
		t.Fatalf("ListObjects failed: %v", err)
	}

	if len(objs) != 2 {
		t.Fatalf("Expected 2 objects, got %d", len(objs))
	}

	if objs[0].Key != "postgres/20261014-020000_daily.sql.gz" || objs[0].Size != 1048576 {
		t.Errorf("Object 0 mismatch: %+v", objs[0])
	}
	if objs[1].Key != "postgres/20261014-040000_pre-deploy.sql.gz" || objs[1].Size != 2097152 {
		t.Errorf("Object 1 mismatch: %+v", objs[1])
	}
}

func TestGzipCompressionDecompression(t *testing.T) {
	// Verify gzip streaming compression and decompression match
	originalData := "INSERT INTO accounts (id, balance) VALUES (1, 1000000);\n"

	var compressedBuf bytes.Buffer
	gw := gzip.NewWriter(&compressedBuf)
	_, err := gw.Write([]byte(originalData))
	if err != nil {
		t.Fatalf("Failed to write to gzip writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("Failed to close gzip writer: %v", err)
	}

	gr, err := gzip.NewReader(&compressedBuf)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	if string(decompressed) != originalData {
		t.Errorf("Decompressed data mismatch: expected %q, got %q", originalData, string(decompressed))
	}
}

func TestManagerBackupMetadata(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Backup.R2Bucket = "custom-backup-bucket"
	cfg.Database.Backup.Prefix = "postgres/uat"
	cfg.Identity.NodeID = "node-test-1"

	// Test ListBackups
	listXML := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>custom-backup-bucket</Name>
</ListBucketResult>`
	listServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(listXML))
	}))
	defer listServer.Close()

	dumper := NewPostgresDumper("host_native", "postgresql", "127.0.0.1", 5432, "postgres", "postgres")
	listR2 := NewR2Client(listServer.URL, "key", "secret")
	mgrWithList := NewManager(dumper, listR2, nil, cfg, nil)

	items, err := mgrWithList.ListBackups(context.Background())
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("Expected 0 items, got %d", len(items))
	}
}
