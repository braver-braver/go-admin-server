package users

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/braver-braver/go-admin-server/internal/apierr"
	"github.com/braver-braver/go-admin-server/internal/httpx"
)

const maxUploadBytes = 2 << 20

// Raster image types only: SVG can carry script and is served from the API
// origin, so it is rejected even though it is an image/* type.
var allowedImageTypes = []string{"image/png", "image/jpeg", "image/gif", "image/webp"}

var (
	errFileRequired = apierr.New(422, "FILE_REQUIRED", "请选择要上传的文件。")
	errFileType     = apierr.New(422, "UNSUPPORTED_FILE_TYPE", "仅支持图片文件。")
	errFileTooLarge = apierr.New(422, "FILE_TOO_LARGE", "文件大小不能超过 2MB。")
	uploadIDPattern = regexp.MustCompile(`^[0-9a-f-]{36}$`)
)

func (m *Module) upload(c *httpx.Ctx) {
	w, r := c.W, c.R
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		httpx.WriteError(w, errFileRequired)
		return
	}
	for {
		part, err := mr.NextPart()
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			httpx.WriteError(w, errFileTooLarge)
			return
		}
		if err != nil {
			httpx.WriteError(w, errFileRequired)
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			continue
		}
		m.storeUpload(c, part.FileName(), part.Header.Get("Content-Type"), part)
		return
	}
}

func (m *Module) storeUpload(c *httpx.Ctx, name, declared string, src io.Reader) {
	w := c.W
	data, err := io.ReadAll(io.LimitReader(src, maxUploadBytes+1))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) || len(data) > maxUploadBytes {
		httpx.WriteError(w, errFileTooLarge)
		return
	}
	if err != nil {
		httpx.WriteError(w, errFileRequired)
		return
	}
	// Trust the bytes, not the declared type.
	sniffed := http.DetectContentType(data)
	mediaType, _, _ := mime.ParseMediaType(declared)
	if !slices.Contains(allowedImageTypes, sniffed) || (mediaType != "" && mediaType != sniffed && !(mediaType == "image/jpg" && sniffed == "image/jpeg")) {
		httpx.WriteError(w, errFileType)
		return
	}
	id := httpx.NewID()
	if err := os.MkdirAll(m.uploadDir, 0o750); err != nil {
		c.Fail(err)
		return
	}
	if err := os.WriteFile(filepath.Join(m.uploadDir, id), data, 0o640); err != nil {
		c.Fail(err)
		return
	}
	up := Upload{ID: id, Name: filepath.Base(name), ContentType: sniffed, Size: int64(len(data)), UploadedBy: c.User().ID}
	if err := m.repo.CreateUpload(c.Context(), up); err != nil {
		c.Fail(err)
		return
	}
	httpx.WriteData(w, http.StatusOK, map[string]any{
		"id": up.ID, "name": up.Name, "url": "/api/v1/uploads/" + up.ID, "contentType": up.ContentType, "size": up.Size,
	})
}

// download serves an uploaded file to accounts that can read business users,
// whose avatars these files are. Not part of the frontend contract yet.
func (m *Module) download(c *httpx.Ctx) {
	w, r := c.W, c.R
	id := r.PathValue("id")
	if !uploadIDPattern.MatchString(id) {
		httpx.WriteError(w, apierr.New(404, "NOT_FOUND", "文件不存在。"))
		return
	}
	up, err := m.repo.GetUpload(r.Context(), id)
	if err != nil {
		c.Fail(err)
		return
	}
	if up == nil {
		httpx.WriteError(w, apierr.New(404, "NOT_FOUND", "文件不存在。"))
		return
	}
	data, err := os.ReadFile(filepath.Join(m.uploadDir, id))
	if err != nil {
		c.Fail(err)
		return
	}
	w.Header().Set("Content-Type", up.ContentType)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}
