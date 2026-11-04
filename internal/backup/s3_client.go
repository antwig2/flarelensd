package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// R2Client is a lightweight, zero-dependency AWS S3 / Cloudflare R2 compatible client
type R2Client struct {
	endpoint        string
	accessKeyID     string
	secretAccessKey string
	region          string
	httpClient      *http.Client
}

func NewR2Client(endpoint, accessKeyID, secretAccessKey string) *R2Client {
	endpoint = strings.TrimRight(endpoint, "/")
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}

	return &R2Client{
		endpoint:        endpoint,
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          "auto", // Cloudflare R2 default region is auto
		httpClient: &http.Client{
			Timeout: 10 * time.Minute, // Long timeout for large streaming pg_dumps
		},
	}
}

// PutObject streams an object directly into Cloudflare R2
func (c *R2Client) PutObject(ctx context.Context, bucket, key string, data io.Reader, size int64, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	key = strings.TrimPrefix(key, "/")
	targetURL := fmt.Sprintf("%s/%s/%s", c.endpoint, bucket, key)

	// In memory payload buffer if size > 0, or streaming reader
	var body io.Reader = data
	payloadHash := "UNSIGNED-PAYLOAD"

	if size <= 0 {
		buf, err := io.ReadAll(data)
		if err != nil {
			return fmt.Errorf("failed to read data stream: %w", err)
		}
		size = int64(len(buf))
		body = bytes.NewReader(buf)
		payloadHash = sha256Hex(buf)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", targetURL, body)
	if err != nil {
		return err
	}

	req.ContentLength = size
	req.Header.Set("Content-Type", contentType)

	c.signRequest(req, payloadHash)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload object to R2: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("r2 put object failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// GetObject streams an object from Cloudflare R2
func (c *R2Client) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	key = strings.TrimPrefix(key, "/")
	targetURL := fmt.Sprintf("%s/%s/%s", c.endpoint, bucket, key)

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	c.signRequest(req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") // empty body hash

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get object from R2: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("r2 get object failed with status %d: %s", resp.StatusCode, string(body))
	}

	return resp.Body, nil
}

// S3Object represents a file stored in the R2 bucket
type S3Object struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}

type listBucketResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
}

// ListObjects lists objects matching prefix in R2 bucket
func (c *R2Client) ListObjects(ctx context.Context, bucket, prefix string) ([]S3Object, error) {
	targetURL := fmt.Sprintf("%s/%s?prefix=%s", c.endpoint, bucket, url.QueryEscape(prefix))

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	c.signRequest(req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects in R2: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("r2 list objects failed with status %d: %s", resp.StatusCode, string(body))
	}

	var xmlResult listBucketResult
	if err := xml.NewDecoder(resp.Body).Decode(&xmlResult); err != nil {
		return nil, err
	}

	objects := make([]S3Object, len(xmlResult.Contents))
	for i, item := range xmlResult.Contents {
		objects[i] = S3Object{
			Key:          item.Key,
			Size:         item.Size,
			LastModified: item.LastModified,
		}
	}

	return objects, nil
}

// AWS SigV4 Signer
func (c *R2Client) signRequest(req *http.Request, payloadHash string) {
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// 1. Build Canonical Headers
	headersToSign := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headersToSign = append(headersToSign, "content-type")
	}
	sort.Strings(headersToSign)

	var canonicalHeaders strings.Builder
	for _, h := range headersToSign {
		val := ""
		if h == "host" {
			val = req.URL.Host
		} else {
			val = req.Header.Get(h)
		}
		canonicalHeaders.WriteString(fmt.Sprintf("%s:%s\n", h, strings.TrimSpace(val)))
	}
	signedHeaders := strings.Join(headersToSign, ";")

	// 2. Build Canonical Request
	query := req.URL.RawQuery
	canonicalReq := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		req.URL.Path,
		query,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	)

	// 3. String to Sign
	credScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region)
	canonHash := sha256Hex([]byte(canonicalReq))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credScope, canonHash)

	// 4. Derive Signing Key
	kSecret := []byte("AWS4" + c.secretAccessKey)
	kDate := hmacSHA256(kSecret, []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(c.region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// 5. Compute Signature
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	// 6. Set Authorization Header
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKeyID,
		credScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
