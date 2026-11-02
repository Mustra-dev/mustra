package server

import (
	"fmt"
	"os"
)

// A backup's dump only knows the tables that existed when it was taken.
// pg_dump --clean drops and recreates those, but a table added by a later
// release survives the restore, and if it has a foreign key into a dumped
// table the dump's own "DROP CONSTRAINT users_pkey" fails ("other objects
// depend on it") and the whole restore is refused. That is exactly the
// documented path for a backup taken before an upgrade (oidc_identities
// references users since the per-agent identity release), so every such
// restore failed.
//
// restoreFKPreamble and restoreFKPostamble run in the same transaction as
// the dump. The preamble records every foreign key in the public schema and
// drops it, so nothing the dump drops is depended on. The postamble puts
// back each one the dump did not recreate itself: rows that now point at a
// row the restored database does not have are deleted (or nulled for ON
// DELETE SET NULL), which is what the constraint would have done had the
// parent rows been deleted, and the constraint is re-added validated. Rows
// in surviving tables that are still consistent are kept: agent_credentials,
// for one, has no foreign key and keeps every enrolled endpoint able to
// connect after a restore.
//
// search_path is emptied first so pg_get_constraintdef qualifies the
// referenced table: the dump sets search_path to ” as well, and the
// postamble runs after it.
const restoreFKPreamble = `SET search_path = '';
CREATE TEMP TABLE mustra_restore_fks ON COMMIT DROP AS
SELECT n.nspname::text AS sch, t.relname::text AS tbl, c.conname::text AS conname,
       pg_catalog.pg_get_constraintdef(c.oid) AS def, c.confdeltype::text AS deltype,
       pn.nspname::text AS psch, pt.relname::text AS ptbl,
       ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY k(num, ord)
             JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.num ORDER BY k.ord) AS cols,
       ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(c.confkey) WITH ORDINALITY k(num, ord)
             JOIN pg_catalog.pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.num ORDER BY k.ord) AS pcols
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
JOIN pg_catalog.pg_class pt ON pt.oid = c.confrelid
JOIN pg_catalog.pg_namespace pn ON pn.oid = pt.relnamespace
WHERE c.contype = 'f' AND n.nspname = 'public';
DO $mustra$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_temp.mustra_restore_fks LOOP
    EXECUTE pg_catalog.format('ALTER TABLE %I.%I DROP CONSTRAINT %I', r.sch, r.tbl, r.conname);
  END LOOP;
END
$mustra$;
`

const restoreFKPostamble = `DO $mustra$
DECLARE
  r record;
  child regclass;
  matched text;
  present text;
  nulls text;
BEGIN
  FOR r IN SELECT * FROM pg_temp.mustra_restore_fks LOOP
    child := pg_catalog.to_regclass(pg_catalog.format('%I.%I', r.sch, r.tbl));
    IF child IS NULL OR pg_catalog.to_regclass(pg_catalog.format('%I.%I', r.psch, r.ptbl)) IS NULL THEN
      CONTINUE;
    END IF;
    -- The dump recreated it (a table the backup knows): nothing to do.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid = child AND conname = r.conname) THEN
      CONTINUE;
    END IF;
    SELECT pg_catalog.string_agg(pg_catalog.format('p.%I = c.%I', r.pcols[i], r.cols[i]), ' AND '),
           pg_catalog.string_agg(pg_catalog.format('c.%I IS NOT NULL', r.cols[i]), ' AND '),
           pg_catalog.string_agg(pg_catalog.format('%I = NULL', r.cols[i]), ', ')
      INTO matched, present, nulls
      FROM pg_catalog.generate_subscripts(r.cols, 1) AS i;
    IF r.deltype = 'n' THEN
      EXECUTE pg_catalog.format('UPDATE %I.%I c SET %s WHERE %s AND NOT EXISTS (SELECT 1 FROM %I.%I p WHERE %s)',
        r.sch, r.tbl, nulls, present, r.psch, r.ptbl, matched);
    ELSE
      EXECUTE pg_catalog.format('DELETE FROM %I.%I c WHERE %s AND NOT EXISTS (SELECT 1 FROM %I.%I p WHERE %s)',
        r.sch, r.tbl, present, r.psch, r.ptbl, matched);
    END IF;
    EXECUTE pg_catalog.format('ALTER TABLE %I.%I ADD CONSTRAINT %I %s', r.sch, r.tbl, r.conname, r.def);
  END LOOP;
END
$mustra$;
`

// restoreWrapperFiles writes the preamble and postamble next to the dump
// and returns them with a cleanup. They are ours, not the archive's, so
// they are not put through the dump screen.
func restoreWrapperFiles() (pre, post string, cleanup func(), err error) {
	write := func(pattern, body string) (string, error) {
		f, err := os.CreateTemp("", pattern)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := f.WriteString(body); err != nil {
			os.Remove(f.Name())
			return "", err
		}
		return f.Name(), nil
	}
	if pre, err = write("mustra-restore-pre-*.sql", restoreFKPreamble); err != nil {
		return "", "", nil, fmt.Errorf("preparing the restore: %w", err)
	}
	if post, err = write("mustra-restore-post-*.sql", restoreFKPostamble); err != nil {
		os.Remove(pre)
		return "", "", nil, fmt.Errorf("preparing the restore: %w", err)
	}
	return pre, post, func() { os.Remove(pre); os.Remove(post) }, nil
}

// restorePsqlArgs is the psql command line for a restore: the dump between
// the foreign-key preamble and postamble, all in one transaction, stopping
// at the first error.
func restorePsqlArgs(dsn, pre, dump, post string) []string {
	// --no-psqlrc: nothing from the server's home directory joins in.
	return []string{"--no-psqlrc", "--dbname", dsn, "-v", "ON_ERROR_STOP=1", "--single-transaction",
		"--file", pre, "--file", dump, "--file", post}
}
