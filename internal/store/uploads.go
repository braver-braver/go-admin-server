package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Upload is the metadata of a stored file; the bytes live in file storage.
type Upload struct {
	ID          string
	Name        string
	ContentType string
	Size        int64
	UploadedBy  string
}

func (s *Store) CreateUpload(ctx context.Context, u Upload) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO uploads (id, name, content_type, size, uploaded_by) VALUES ($1,$2,$3,$4,$5)`,
		u.ID, u.Name, u.ContentType, u.Size, u.UploadedBy)
	return err
}

// GetUpload returns the metadata of an upload, or nil.
func (s *Store) GetUpload(ctx context.Context, id string) (*Upload, error) {
	var u Upload
	err := s.pool.QueryRow(ctx, `SELECT id, name, content_type, size, uploaded_by FROM uploads WHERE id = $1`, id).
		Scan(&u.ID, &u.Name, &u.ContentType, &u.Size, &u.UploadedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &u, err
}
