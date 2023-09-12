# leaf

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=white)](https://pkg.go.dev/github.com/creachadair/leaf)

Lightweight Encrypted Archive Format

## Data Formats

LEAF is a lightweight encrypted storage representation for small databases of important data like passwords and private notes.

A LEAF file is a JSON object with the following format:

```json
{
  "leaf": 1,
  "key": "<base64-encoded-encrypted-data-key>",
  "data": "<base64-encoded-encrypted-data>"
}
```

All encryption is performed using the AEAD construction with the ChaCha20-Poly1305 algorithm with a 256-bit key and a 24-bit nonce.

The _data key_ (`"key"`) is encrypted with an _access key_ supplied by the user. Typically this may be generated randomly and stored in a secure location, or generated from a passphrase via a KDF like scrypt or hkdf.

The _data record_ is encrypted with the data key.

The plaintext data record is a JSON object with the following structure:

```json
{
  "log": [
     <log-record>,
     ...
  ]
}
```

A _log_record_ is a JSON object in the following format:

```json
{
  "op": "<opcode>",
  "A": <value<,
  "B": <value>,
  "C": <value>,
  "time": <timestamp>
}
```

### Operations

| op           | A     | B   | C     | description                                  |
|--------------|-------|-----|-------|----------------------------------------------|
| create-table | name  | -   | -     | create a (new) table with the given name     |
| delete-table | name  | -   | -     | delete an existing table with the given name |
| rename-table | old   | new | -     | rename an existing table from old to new     |
| clear-table  | name  | -   | -     | remove all entries from the given table      |
| update       | table | key | value | insert or replace key with value in table    |
| delete       | table | key | -     | delete key from table                        |
| rename       | table | old | new   | rename old to new in table                   |

### Timestamps

Timestamps are recorded as an integer count of milliseconds since the Unix epoch.
