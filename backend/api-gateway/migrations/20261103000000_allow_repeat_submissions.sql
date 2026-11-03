-- A file hash identified one global submission row, so re-uploading a file someone
-- else had submitted overwrote their submission's owner and reset it to pending.
-- Each submission is now its own row; the plain index on file_hash stays for lookups.
ALTER TABLE submissions DROP CONSTRAINT IF EXISTS submissions_file_hash_key;
