package server

// Backup and restore.
//
// What is worth protecting here is the database: every endpoint's identity
// and history, saved queries, policies, playbooks, roles and audit. Package
// files -- the installers staged to endpoints -- are deliberately optional,
// because they are large, they are re-uploadable, and including them by
// default turns a thirty-second nightly job into a multi-gigabyte one.
//
// The dump is produced by pg_dump rather than by walking tables in Go. The
// schema is handwritten SQL with JSONB, arrays, partial indexes and
// generated columns; a hand-rolled exporter would be a second, worse
// definition of the schema that drifts from schema.sql the first time
// somebody adds a column.
//
// Two things are NOT in a backup, and the console says so where an operator
// will read it:
//
//   - MUSTRA_CREDENTIAL_ENCRYPTION_KEY, which lives in .env. Stored
//     credentials are encrypted with it, so restoring a database onto a
//     deployment with a different key leaves those rows undecryptable. The
//     key is excluded on purpose: a backup that carries the key it protects
//     protects nothing.
//   - The NATS certificates, also on the host. Losing them takes the bus
//     down, and they are regenerated rather than restored.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/version"
)

const (
	backupManifestName = "manifest.json"
	backupDatabaseName = "database.sql"
	backupPackageDir   = "package-files"

	// pg_dump on a large fleet is minutes, not seconds, and a backup that is
	// killed halfway is worse than one that took a while.
	backupTimeout = 30 * time.Minute
)

// BackupManifest describes an archive well enough to refuse a bad one
// before any of it is applied.
type BackupManifest struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by"`
	ServerVersion string    `json:"server_version"`
	// IncludesPackageFiles records what the operator chose, so a restore can
	// say what it is about to put back rather than guessing from the tar.
	IncludesPackageFiles bool   `json:"includes_package_files"`
	DatabaseSHA256       string `json:"database_sha256"`
	DatabaseBytes        int64  `json:"database_bytes"`
	// Note carries the operator's own reason for taking it.
	Note string `json:"note,omitempty"`
	// PackageFilesSHA256 covers every package-file member, in archive
	// order, so they are as tamper-evident as the dump.
	PackageFilesSHA256 string `json:"package_files_sha256,omitempty"`
	// Signature is HMAC-SHA256 over the rest of the manifest under this
	// server's backup signing key; see backup_sign.go.
	Signature string `json:"signature,omitempty"`
}

// maxRestoreBytes caps what a restore will decompress, across all members.
// A few hundred kilobytes of gzip can otherwise expand to fill the disk.
func maxRestoreBytes() int64 {
	if v := os.Getenv("MUSTRA_RESTORE_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 32 << 30
}

// errRestoreRefused marks an archive refused before anything was applied
// (not a backup, unsigned, edited, or screened out), as opposed to a
// restore that failed. The handler answers it 422: the archive is the
// caller's to fix.
var errRestoreRefused = errors.New("restore refused")

// errRestoreTooLarge is returned when an archive expands past the cap.
var errRestoreTooLarge = fmt.Errorf("%w: the archive expands past the restore size limit (MUSTRA_RESTORE_MAX_BYTES)", errRestoreRefused)

// archiveError explains a failure to read an archive. A file that is
// malformed is refused, as the caller's to fix; one the server could not
// read at all (missing, unreadable, a disk error) is the server's fault.
func archiveError(what string, err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%w: %s: %w", errRestoreRefused, what, err)
}

// budgetReader fails once more than the remaining budget has been read.
type budgetReader struct {
	r      io.Reader
	budget *int64
}

func (b budgetReader) Read(p []byte) (int, error) {
	if *b.budget <= 0 {
		return 0, errRestoreTooLarge
	}
	if int64(len(p)) > *b.budget {
		p = p[:*b.budget]
	}
	n, err := b.r.Read(p)
	*b.budget -= int64(n)
	return n, err
}

// BackupRecord is a manifest plus what is true of the file on disk.
type BackupRecord struct {
	BackupManifest
	Filename string `json:"filename"`
	Bytes    int64  `json:"bytes"`
}

func backupDir() string {
	if d := os.Getenv("MUSTRA_BACKUP_DIR"); d != "" {
		return d
	}
	return "/var/lib/mustra/output/backups"
}

// pgToolEnv hands the connection string to pg_dump/psql through the
// environment rather than the command line, so it cannot be read out of the
// process table by anything else on the host.
func pgToolEnv(dsn string) []string {
	return append(os.Environ(), "PGCONNECT_TIMEOUT=10", "MUSTRA_PG_DSN="+dsn)
}

// createBackup writes one archive and returns what it wrote. It never
// touches an existing archive, so a failure leaves every previous backup
// exactly as it was.
func (s *Server) createBackup(ctx context.Context, by, note string, includePackages bool) (*BackupRecord, error) {
	if err := os.MkdirAll(backupDir(), 0o700); err != nil {
		return nil, fmt.Errorf("creating the backup directory: %w", err)
	}
	// Resolved before any work: an archive that cannot be signed cannot be
	// restored either.
	signingKey, err := s.backupSigningKey()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()

	id := idgen.New("bk-")
	created := time.Now().UTC()
	final := filepath.Join(backupDir(), id+".tar.gz")

	// Written under a temporary name and renamed at the end: a half-written
	// archive that is listed as a backup is the kind of thing somebody finds
	// out about on the day they need it.
	tmp, err := os.CreateTemp(backupDir(), ".partial-*")
	if err != nil {
		return nil, fmt.Errorf("creating the archive: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // no-op once renamed
	}()

	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)

	dumpSHA, dumpBytes, err := s.writeDatabaseDump(ctx, tw)
	if err != nil {
		return nil, err
	}

	pkgDigest := newTreeDigest()
	if includePackages {
		if err := addTreeToTar(tw, packageFileDir(), backupPackageDir, pkgDigest); err != nil {
			return nil, fmt.Errorf("adding package files: %w", err)
		}
	}

	manifest := BackupManifest{
		ID: id, CreatedAt: created, CreatedBy: by,
		ServerVersion:        version.Version,
		IncludesPackageFiles: includePackages,
		DatabaseSHA256:       dumpSHA,
		DatabaseBytes:        dumpBytes,
		Note:                 strings.TrimSpace(note),
	}
	if includePackages {
		manifest.PackageFilesSHA256 = pkgDigest.sum()
	}
	manifest.Signature = manifestMAC(signingKey, manifest)
	blob, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeTarFile(tw, backupManifestName, blob); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("closing the archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("closing the archive: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("flushing the archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing the archive: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return nil, fmt.Errorf("publishing the archive: %w", err)
	}
	if err := os.Chmod(final, 0o600); err != nil {
		s.logger.Warn("could not tighten permissions on a backup", "file", final, "error", err)
	}

	fi, err := os.Stat(final)
	if err != nil {
		return nil, err
	}
	return &BackupRecord{BackupManifest: manifest, Filename: filepath.Base(final), Bytes: fi.Size()}, nil
}

// writeDatabaseDump streams pg_dump straight into the tar, hashing as it
// goes. tar needs a size up front, so the dump lands in a temporary file
// first -- streaming it twice would mean dumping twice, and two dumps taken
// a minute apart are not the same database.
func (s *Server) writeDatabaseDump(ctx context.Context, tw *tar.Writer) (string, int64, error) {
	dump, err := os.CreateTemp("", "mustra-dump-*.sql")
	if err != nil {
		return "", 0, fmt.Errorf("staging the dump: %w", err)
	}
	defer func() { dump.Close(); os.Remove(dump.Name()) }()

	// --clean --if-exists so the dump can be applied to a database that
	// already has these objects, which is every restore that is not onto an
	// empty deployment. --no-owner/--no-privileges so it restores under
	// whatever role the target uses rather than demanding the source's.
	cmd := exec.CommandContext(ctx, "pg_dump",
		"--clean", "--if-exists", "--no-owner", "--no-privileges", "--format=plain",
		"--dbname", s.cfg.PostgresDSN)
	cmd.Env = pgToolEnv(s.cfg.PostgresDSN)
	cmd.Stdout = dump
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("pg_dump failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	if _, err := dump.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	h := sha256.New()
	size, err := io.Copy(h, dump)
	if err != nil {
		return "", 0, err
	}
	if size == 0 {
		return "", 0, fmt.Errorf("pg_dump produced an empty dump")
	}
	if _, err := dump.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: backupDatabaseName, Mode: 0o600, Size: size, ModTime: time.Now(), Typeflag: tar.TypeReg,
	}); err != nil {
		return "", 0, err
	}
	if _, err := io.Copy(tw, dump); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func writeTarFile(tw *tar.Writer, name string, body []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: int64(len(body)), ModTime: time.Now(), Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

// addTreeToTar copies a directory in under prefix. A missing directory is
// not an error: a deployment that has never staged a package file has none.
func addTreeToTar(tw *tar.Writer, root, prefix string, digest *treeDigest) error {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		name := filepath.ToSlash(filepath.Join(prefix, rel))
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		h := sha256.New()
		if _, err = io.Copy(io.MultiWriter(tw, h), f); err != nil {
			return err
		}
		if digest != nil {
			digest.add(name, h.Sum(nil))
		}
		return nil
	})
}

// listBackups reads the directory rather than a table. The archives are the
// record; a table listing a file that is not there, or missing one that is,
// is a second source of truth for no benefit.
func (s *Server) listBackups() ([]BackupRecord, error) {
	entries, err := os.ReadDir(backupDir())
	if os.IsNotExist(err) {
		return []BackupRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []BackupRecord{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		rec, err := readBackupRecord(filepath.Join(backupDir(), e.Name()))
		if err != nil {
			s.logger.Warn("skipping an unreadable backup", "file", e.Name(), "error", err)
			continue
		}
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func readBackupRecord(path string) (*BackupRecord, error) {
	m, err := readManifest(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return &BackupRecord{BackupManifest: *m, Filename: filepath.Base(path), Bytes: fi.Size()}, nil
}

func readManifest(path string) (*BackupManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no %s in the archive", backupManifestName)
		}
		if err != nil {
			return nil, err
		}
		if h.Name != backupManifestName {
			continue
		}
		var m BackupManifest
		if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&m); err != nil {
			return nil, fmt.Errorf("unreadable manifest: %w", err)
		}
		return &m, nil
	}
}

// backupPath resolves an id to a file inside the backup directory. The id
// comes from a URL, so it is checked rather than trusted.
func backupPath(id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid backup id")
	}
	path := filepath.Join(backupDir(), id+".tar.gz")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("no such backup")
	}
	return path, nil
}

// --- restore ---------------------------------------------------------
//
// A restore replaces the database this server is running against. It is
// deliberately not a live operation: the dump drops and recreates every
// object, so the pool this process is holding is talking to tables that
// stop existing halfway through. The sequence is therefore validate, apply,
// then exit -- the container's restart policy brings the server back onto
// the restored database with nothing cached from the old one.

// RestoreResult is what the operator is told happened.
type RestoreResult struct {
	Manifest      BackupManifest `json:"manifest"`
	PackageFiles  int            `json:"package_files_restored"`
	RestartingNow bool           `json:"restarting_now"`
}

// restoreBackup applies an archive. Everything that can be checked is
// checked before the first statement runs, because the failure that matters
// is the one that leaves a half-applied database.
//
// external is the administrator's explicit "import an external backup":
// the archive need not carry this server's signature, and the dump is
// screened strictly instead (see sqlscan.go). Without it, an unsigned or
// foreign archive is refused.
func (s *Server) restoreBackup(ctx context.Context, path, by string, external bool) (*RestoreResult, error) {
	manifest, err := readManifest(path)
	if err != nil {
		return nil, archiveError("this file is not a mustra backup", err)
	}
	key, kerr := s.backupSigningKey()
	signed := kerr == nil && verifyManifest(key, *manifest)
	if !signed && !external {
		return nil, fmt.Errorf("%w: this archive was not signed by this server (it is unsigned, from another deployment, "+
			"or was edited); an administrator can restore it with \"Import external backup\", which screens it first", errRestoreRefused)
	}
	budget := maxRestoreBytes()
	pkgDigest := newTreeDigest()

	dump, err := os.CreateTemp("", "mustra-restore-*.sql")
	if err != nil {
		return nil, err
	}
	defer func() { dump.Close(); os.Remove(dump.Name()) }()

	h := sha256.New()
	var dumpSize int64
	packageFiles := 0
	stagedPackages := ""

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(budgetReader{r: gz, budget: &budget})
	seenDump := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, archiveError("reading the archive", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		switch {
		case hdr.Name == backupDatabaseName:
			if seenDump {
				return nil, fmt.Errorf("%w: the archive holds more than one database dump", errRestoreRefused)
			}
			seenDump = true
			dumpSize, err = io.Copy(io.MultiWriter(dump, h), tr)
			if err != nil {
				return nil, archiveError("extracting the dump", err)
			}
		case strings.HasPrefix(hdr.Name, backupPackageDir+"/"):
			if stagedPackages == "" {
				if stagedPackages, err = os.MkdirTemp("", "mustra-pkg-*"); err != nil {
					return nil, err
				}
			}
			fh := sha256.New()
			n, err := extractInto(io.TeeReader(tr, fh), hdr, stagedPackages, backupPackageDir+"/")
			if err != nil {
				return nil, err
			}
			pkgDigest.add(hdr.Name, fh.Sum(nil))
			packageFiles += n
		}
	}
	if stagedPackages != "" {
		defer os.RemoveAll(stagedPackages)
	}

	if dumpSize == 0 {
		return nil, fmt.Errorf("%w: the archive has no database dump in it", errRestoreRefused)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != manifest.DatabaseSHA256 {
		return nil, fmt.Errorf("%w: the dump does not match its checksum; this archive is damaged or was edited", errRestoreRefused)
	}
	if signed && packageFiles > 0 && pkgDigest.sum() != manifest.PackageFilesSHA256 {
		return nil, fmt.Errorf("%w: the package files do not match the signed manifest; this archive was edited", errRestoreRefused)
	}
	// psql is a shell as much as a SQL client: refuse meta-commands and
	// COPY … PROGRAM before it sees a byte. An external archive is held to
	// the stricter screen.
	if _, err := dump.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := scanDump(dump, !signed); err != nil {
		s.logger.Error("restore refused by the dump screen", "backup", manifest.ID, "external", !signed, "error", err)
		return nil, fmt.Errorf("%w: the dump was refused: %w", errRestoreRefused, err)
	}

	// Nothing has been changed yet. From here on it has.
	s.logger.Warn("restoring the database from a backup", "backup", manifest.ID,
		"taken", manifest.CreatedAt, "by", by)

	if err := s.applyDump(ctx, dump.Name()); err != nil {
		return nil, err
	}
	if stagedPackages != "" {
		if err := replaceTree(filepath.Join(stagedPackages, backupPackageDir), packageFileDir()); err != nil {
			// The database is already back; say so rather than reporting a
			// blanket failure that reads as "nothing was restored".
			s.logger.Error("the database was restored but package files were not", "error", err)
			return nil, fmt.Errorf("the database was restored, but package files could not be: %w", err)
		}
	}
	return &RestoreResult{Manifest: *manifest, PackageFiles: packageFiles, RestartingNow: true}, nil
}

// applyDump runs the dump through psql with ON_ERROR_STOP, so a restore
// that goes wrong stops at the first bad statement instead of continuing
// and leaving a database that is neither the old one nor the new one.
func (s *Server) applyDump(ctx context.Context, file string) error {
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()

	// The server's own pool is holding the objects the dump is about to
	// drop. Those connections are going away when this process exits in a
	// moment anyway, so close them now rather than deadlocking against
	// ourselves.
	term := exec.CommandContext(ctx, "psql", "--dbname", s.cfg.PostgresDSN, "-v", "ON_ERROR_STOP=1", "-c",
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
			"WHERE datname = current_database() AND pid <> pg_backend_pid()")
	term.Env = pgToolEnv(s.cfg.PostgresDSN)
	if out, err := term.CombinedOutput(); err != nil {
		s.logger.Warn("could not close existing database connections before restoring",
			"error", err, "output", strings.TrimSpace(string(out)))
	}

	// Tables a newer release added survive the dump's --clean; their
	// foreign keys into dumped tables are lifted around it (see
	// backup_restore_fk.go), or an older backup could never be restored.
	pre, post, cleanup, err := restoreWrapperFiles()
	if err != nil {
		return err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, "psql", restorePsqlArgs(s.cfg.PostgresDSN, pre, file, post)...)
	cmd.Env = pgToolEnv(s.cfg.PostgresDSN)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restoring the dump failed, and nothing was committed: %w: %s",
			err, lastLines(string(out), 5))
	}
	return nil
}

func extractInto(tr io.Reader, hdr *tar.Header, root, prefix string) (int, error) {
	rel := strings.TrimPrefix(hdr.Name, prefix)
	// Archives are operator-supplied, so a member that climbs out of the
	// destination is refused rather than written.
	if rel == "" || strings.Contains(rel, "..") || filepath.IsAbs(rel) {
		return 0, fmt.Errorf("%w: the archive contains an unsafe path: %s", errRestoreRefused, hdr.Name)
	}
	dest := filepath.Join(root, prefix, filepath.FromSlash(rel))
	if !strings.HasPrefix(dest, filepath.Clean(root)+string(os.PathSeparator)) {
		return 0, fmt.Errorf("%w: the archive contains an unsafe path: %s", errRestoreRefused, hdr.Name)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := io.Copy(f, tr); err != nil {
		return 0, err
	}
	return 1, nil
}

// replaceTree swaps staged content in, keeping the previous copy until the
// new one is in place -- the same shape as the agent installer, for the
// same reason.
func replaceTree(staged, dest string) error {
	if _, err := os.Stat(staged); err != nil {
		return nil
	}
	previous := dest + ".previous"
	_ = os.RemoveAll(previous)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, previous); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	if err := os.Rename(staged, dest); err != nil {
		if _, statErr := os.Stat(previous); statErr == nil {
			_ = os.Rename(previous, dest)
		}
		return err
	}
	_ = os.RemoveAll(previous)
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "; ")
}

// --- retention and the nightly job -----------------------------------

const (
	settingBackupScheduleEnabled = "backup.schedule_enabled"
	settingBackupHourUTC         = "backup.hour_utc"
	settingBackupKeep            = "backup.keep"
	settingBackupIncludePackages = "backup.include_package_files"

	backupKeepDefault = 7
	backupHourDefault = 3
)

// BackupSettings is the schedule as the console edits it. PUT
// /api/backups/settings replaces all of it: enabled or
// include_package_files left out is false, and hour_utc left out is
// midnight.
type BackupSettings struct {
	Enabled             bool `json:"enabled"`
	HourUTC             int  `json:"hour_utc"`
	Keep                int  `json:"keep" api:"required"`
	IncludePackageFiles bool `json:"include_package_files"`
}

func (s *Server) backupSettings(ctx context.Context) BackupSettings {
	all, err := s.store.GetAllSettings(ctx)
	if err != nil {
		s.logger.Warn("could not read the backup settings", "error", err)
		all = map[string]string{}
	}
	cfg := BackupSettings{
		Enabled:             all[settingBackupScheduleEnabled] == "true",
		HourUTC:             atoiOr(all[settingBackupHourUTC], backupHourDefault),
		Keep:                atoiOr(all[settingBackupKeep], backupKeepDefault),
		IncludePackageFiles: all[settingBackupIncludePackages] == "true",
	}
	if cfg.HourUTC < 0 || cfg.HourUTC > 23 {
		cfg.HourUTC = backupHourDefault
	}
	if cfg.Keep < 1 {
		cfg.Keep = backupKeepDefault
	}
	return cfg
}

// pruneBackups keeps the newest `keep` archives. It runs after a successful
// backup only: pruning on a failed run would delete a good archive to make
// room for one that was never written.
func (s *Server) pruneBackups(keep int) {
	if keep < 1 {
		return
	}
	all, err := s.listBackups()
	if err != nil {
		s.logger.Warn("could not list backups to prune", "error", err)
		return
	}
	if len(all) <= keep {
		return
	}
	for _, old := range all[keep:] {
		path := filepath.Join(backupDir(), old.Filename)
		if err := os.Remove(path); err != nil {
			s.logger.Warn("could not remove an old backup", "file", old.Filename, "error", err)
			continue
		}
		s.logger.Info("pruned an old backup", "backup", old.ID, "taken", old.CreatedAt)
	}
}

// backupSchedulerLoop takes the nightly backup. It checks every fifteen
// minutes rather than sleeping until the hour, so enabling the schedule or
// moving it takes effect without a restart, and a server that was down at
// the appointed hour still takes one when it comes back that day.
func (s *Server) backupSchedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cfg := s.backupSettings(ctx)
		if !cfg.Enabled {
			continue
		}
		now := time.Now().UTC()
		if now.Hour() != cfg.HourUTC {
			continue
		}
		if s.backupTakenOn(now) {
			continue
		}
		rec, err := s.createBackup(ctx, "scheduled", "nightly", cfg.IncludePackageFiles)
		if err != nil {
			// A backup that silently stops happening is the failure mode
			// this whole feature exists to prevent, so it is a notification,
			// not just a log line.
			s.logger.Error("the scheduled backup failed", "error", err)
			s.notify(ctx, "critical", "backup", "The nightly backup failed",
				err.Error(), "/backup")
			continue
		}
		s.logger.Info("scheduled backup written", "backup", rec.ID, "bytes", rec.Bytes)
		s.pruneBackups(cfg.Keep)
	}
}

// backupTakenOn reports whether a backup already exists for today, which is
// what keeps a fifteen-minute tick from taking four backups in the hour.
func (s *Server) backupTakenOn(now time.Time) bool {
	all, err := s.listBackups()
	if err != nil {
		// Erring towards "already taken" would skip the day's backup on a
		// transient read error, which is the wrong way to be wrong.
		return false
	}
	y, m, d := now.Date()
	for _, b := range all {
		by, bm, bd := b.CreatedAt.UTC().Date()
		if by == y && bm == m && bd == d {
			return true
		}
	}
	return false
}

func atoiOr(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return fallback
		}
		n = n*10 + int(r-'0')
	}
	return n
}
