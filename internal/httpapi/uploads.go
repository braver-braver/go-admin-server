package httpapi

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
	"github.com/braver-braver/go-admin-server/internal/store"
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

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:write")
	if sess == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, errFileRequired)
		return
	}
	for {
		part, err := mr.NextPart()
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, errFileTooLarge)
			return
		}
		if err != nil {
			writeError(w, errFileRequired)
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			continue
		}
		s.storeUpload(w, r, sess, part.FileName(), part.Header.Get("Content-Type"), part)
		return
	}
}

func (s *Server) storeUpload(w http.ResponseWriter, r *http.Request, sess *session, name, declared string, src io.Reader) {
	data, err := io.ReadAll(io.LimitReader(src, maxUploadBytes+1))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) || len(data) > maxUploadBytes {
		writeError(w, errFileTooLarge)
		return
	}
	if err != nil {
		writeError(w, errFileRequired)
		return
	}
	// Trust the bytes, not the declared type.
	sniffed := http.DetectContentType(data)
	mediaType, _, _ := mime.ParseMediaType(declared)
	if !slices.Contains(allowedImageTypes, sniffed) || (mediaType != "" && mediaType != sniffed && !(mediaType == "image/jpg" && sniffed == "image/jpeg")) {
		writeError(w, errFileType)
		return
	}
	id := newID()
	if err := os.MkdirAll(s.cfg.UploadDir, 0o750); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := os.WriteFile(filepath.Join(s.cfg.UploadDir, id), data, 0o640); err != nil {
		s.fail(w, r, err)
		return
	}
	up := store.Upload{ID: id, Name: filepath.Base(name), ContentType: sniffed, Size: int64(len(data)), UploadedBy: sess.user.ID}
	if err := s.store.CreateUpload(r.Context(), up); err != nil {
		s.fail(w, r, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{
		"id": up.ID, "name": up.Name, "url": Prefix + "/uploads/" + up.ID, "contentType": up.ContentType, "size": up.Size,
	})
}

// download serves an uploaded file to accounts that can read business users,
// whose avatars these files are. Not part of the frontend contract yet.
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	sess := s.guard(w, r, "users:read")
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	if !uploadIDPattern.MatchString(id) {
		writeError(w, apierr.New(404, "NOT_FOUND", "文件不存在。"))
		return
	}
	up, err := s.store.GetUpload(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if up == nil {
		writeError(w, apierr.New(404, "NOT_FOUND", "文件不存在。"))
		return
	}
	data, err := os.ReadFile(filepath.Join(s.cfg.UploadDir, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", up.ContentType)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}
