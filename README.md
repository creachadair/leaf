# leaf

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=white)](https://pkg.go.dev/github.com/creachadair/leaf)

Lightweight Encrypted Archive Format (LEAF) is an encrypted storage representation for small databases of important data like passwords and private notes. The store is log-structured, preserving the complete history of changes so that it can be rewound to any previous state.

## Usage Summary

```go
import "github.com/creachadair/leaf"

// Create a file.
f, err := leaf.New(accessKey)
if err != nil {
  log.Fatal(err)
}

// Add tables to the file.
tab := f.Database().Table("bookmarks")

// Add records to the table.
tab.Set("godoc", "https://golang.org")

// Get data from a table.
if u, ok := leaf.Get[string](tab, "godoc"); ok {
  log.Print(u)
}

// Write the file to storage.
if f.IsModified() {
  _, err := f.WriteTo(w)
  if err != nil {
    log.Fatal(err)
  }
}
```

## Data Formats

A LEAF file is a JSON object with the following format:

```json
{
  "leaf": 1,
  "key": "<base64-encoded-encrypted-data-key>",
  "data": "<base64-encoded-encrypted-data>"
}
```

All encryption is performed using the AEAD construction with the ChaCha20-Poly1305 algorithm with a 256-bit key and a 24-byte nonce.

The user must provide a 256-bit (32 byte) _access key_ to create or open a file. Typically this may be generated randomly and stored in a secure location, or generated from a passphrase via a KDF like [scrypt](https://en.wikipedia.org/wiki/Scrypt) or [hkdf](https://en.wikipedia.org/wiki/HKDF).

The _data key_ (`"key"`) is encrypted with the access key.

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

The database is a sequence of log entries recording the complete history of state changes. A _log entry_ is a JSON object with this format:

```json
{
  "op": "<opcode>",
  "table": "<table-name>",
  "key": "<key-name>",
  "value": <value>,
  "time": "<timestamp>"
}
```

The state of the database at any moment in its history can be obtained by scanning the log records from the beginning to that time.

### Operations

The following operations are understood by the log:

| op           | table | key | value | description                                  |
|--------------|-------|-----|-------|----------------------------------------------|
| create-table | name  | -   | -     | create a (new) table with the given name     |
| delete-table | name  | -   | -     | delete an existing table with the given name |
| clear-table  | name  | -   | -     | remove all entries from the given table      |
| update       | table | key | value | insert or replace key with value in table    |
| delete       | table | key | -     | delete key from table                        |

### Timestamps

Timestamps are recorded as an integer count of microseconds since the Unix epoch, as a string.
