package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PackageFile is one payload staged to the endpoint before a package's
// command runs. Only metadata is here; the bytes live on disk.
type PackageFile struct {
	ID        string    `json:"id"`
	PackageID string    `json:"package_id"`
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

const packageFileColumns = `id, package_id, name, size_bytes, sha256, created_at, created_by`

func scanPackageFile(row pgx.Row) (*PackageFile, error) {
	var f PackageFile
	if err := row.Scan(&f.ID, &f.PackageID, &f.Name, &f.SizeBytes,
		&f.SHA256, &f.CreatedAt, &f.CreatedBy); err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *Store) ListPackageFiles(ctx context.Context, packageID string) ([]PackageFile, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+packageFileColumns+` FROM package_files WHERE package_id = $1 ORDER BY name`, packageID)
	if err != nil {
		return nil, fmt.Errorf("list package files: %w", err)
	}
	defer rows.Close()
	var out []PackageFile
	for rows.Next() {
		f, err := scanPackageFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan package file: %w", err)
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

func (s *Store) GetPackageFile(ctx context.Context, id string) (*PackageFile, error) {
	f, err := scanPackageFile(s.pool.QueryRow(ctx,
		`SELECT `+packageFileColumns+` FROM package_files WHERE id = $1`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get package file: %w", err)
	}
	return f, nil
}

func (s *Store) CreatePackageFile(ctx context.Context, f PackageFile) (*PackageFile, error) {
	const q = `
INSERT INTO package_files (id, package_id, name, size_bytes, sha256, created_by)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, size_bytes = EXCLUDED.size_bytes, sha256 = EXCLUDED.sha256
RETURNING ` + packageFileColumns
	out, err := scanPackageFile(s.pool.QueryRow(ctx, q,
		f.ID, f.PackageID, f.Name, f.SizeBytes, f.SHA256, f.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("create package file: %w", err)
	}
	return out, nil
}

func (s *Store) DeletePackageFile(ctx context.Context, id string) error {
	var referenced bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deploy_revisions WHERE jsonb_path_exists(definition,'$.**.id ? (@ == $file)',jsonb_build_object('file',$1::text)))`, id).Scan(&referenced); err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf("file is referenced by a Deploy revision and cannot be deleted")
	}

	if _, err := s.pool.Exec(ctx, `DELETE FROM package_files WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete package file: %w", err)
	}
	return nil
}
