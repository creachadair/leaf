// Package leaf defines a lightweight encrypted archive format for small data.
//
// Files created by this package are encrypted using the AEAD construction over
// the ChaCha20-Poly1305 algorithm with a 256-bit key and a 24-bit nonce.  The
// underlying storage format is JSON.
//
// A file contains a number of named "tables" each of which is a logical map
// from string column names to arbitrary JSON values. The data store does not
// interpret the contents of the tables.
package leaf

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/golang/snappy"
	"golang.org/x/crypto/chacha20poly1305"
)

// AccessKeyLen is the required length in bytes of an access key.
const AccessKeyLen = chacha20poly1305.KeySize // 32 bytes

// formatVersion is the file format version understood by this package.
const formatVersion = 1

// Constants for operations.
const (
	opCreateTable = "create-table"
	opDeleteTable = "delete-table"
	opRenameTable = "rename-table"
	opClearTable  = "clear-table"
	opUpdateKey   = "update"
	opDeleteKey   = "delete"
)

// A File is a LEAF archive file.
type File struct {
	dataKeyEncrypted []byte
	dataKeyPlain     []byte
	db               *Database
}

// WriteTo encodes, encrypts, and writes the current contents of f to w.
// If an error occurs in encoding or encryption, no data are written to w.
// Writing f clears its modification flag, if set.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	if len(f.dataKeyEncrypted) == 0 || len(f.dataKeyPlain) == 0 {
		return 0, errors.New("invalid file: no encryption key present")
	}
	data, err := json.Marshal(f.db)
	if err != nil {
		return 0, fmt.Errorf("encode data: %w", err)
	}
	dataEncrypted, err := encryptWithKey(f.dataKeyPlain, compress(data))
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}
	wf, err := json.Marshal(wireFile{
		V:    formatVersion,
		Key:  f.dataKeyEncrypted,
		Data: dataEncrypted,
	})
	if err != nil {
		return 0, fmt.Errorf("encode file: %w", err)
	}
	nw, err := w.Write(wf)
	if err == nil {
		f.db.dirty = false
	}
	return int64(nw), err
}

// IsModified reports whether the contents of f have been modified.
func (f *File) IsModified() bool { return f.db.IsModified() }

// Database returns the database stored in f.
func (f *File) Database() *Database { return f.db }

// New constructs a new empty File using the specified access key.
// The key must be AccessKeyLen bytes in length.
func New(accessKey []byte) (*File, error) {
	dataKeyPlain := make([]byte, chacha20poly1305.KeySize)
	if _, err := cryptorand.Read(dataKeyPlain); err != nil {
		return nil, fmt.Errorf("generate data key: %w", err)
	}
	dataKeyEncrypted, err := encryptWithKey(accessKey, dataKeyPlain)
	if err != nil {
		return nil, fmt.Errorf("encrypt data key: %w", err)
	}
	return &File{
		dataKeyEncrypted: dataKeyEncrypted, // for storage
		dataKeyPlain:     dataKeyPlain,     // to encrypt data
		db:               newDatabase(nil),
	}, nil
}

// Open reads and decrypts a File from the contents of r using the given
// accessKey. The key must be AccessKeyLen bytes in length.
func Open(accessKey []byte, r io.Reader) (*File, error) {
	// Phase 1: Decode the unencrypted wrapper to get the data key.
	bits, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var wf wireFile
	if err := json.Unmarshal(bits, &wf); err != nil {
		return nil, fmt.Errorf("decode file: %w", err)
	} else if wf.V != formatVersion {
		return nil, fmt.Errorf("version mismatch: got %v, want %v", wf.V, formatVersion)
	}

	// Phase 2: Decrypt the data key with the access key.
	dataKey, err := decryptWithKey(accessKey, wf.Key)
	if err != nil {
		return nil, fmt.Errorf("decrypt data key: %w", err)
	}

	// Phase 3: Decrypt the data payload with the data key.
	payload, err := decryptWithKey(dataKey, wf.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	// Phase 4: Decode the data log.
	var db Database
	if err := json.Unmarshal(decompress(payload), &db); err != nil {
		clear(dataKey)
		return nil, fmt.Errorf("decode data: %w", err)
	}
	db.tabs = tablesFromLog(db.log)
	return &File{
		dataKeyEncrypted: wf.Key,
		dataKeyPlain:     dataKey,
		db:               &db,
	}, nil
}

type wireFile struct {
	V    int64  `json:"leaf"`
	Key  []byte `json:"key"`
	Data []byte `json:"data"`
}

// Database is a database of key-value tables stored in a File.
type Database struct {
	log   []*logEntry
	dirty bool // whether the log was modified

	saved  []*logEntry // the original state of a rewound database
	wasMod bool        // whether saved was also dirty

	tabs map[string]map[string]*logEntry
}

// IsModified reports whether the contents of d have been modified.
func (d *Database) IsModified() bool { return d.dirty }

// TableNames returns a slice of the table names of d in sorted order.
func (d *Database) TableNames() []string {
	out := make([]string, 0, len(d.tabs))
	for tab := range d.tabs {
		out = append(out, tab)
	}
	sort.Strings(out)
	return out
}

// GetTable reports whether d has a table by the given name, and if so returns
// the table.
func (d *Database) GetTable(name string) (Table, bool) {
	if _, ok := d.tabs[name]; ok {
		return Table{name: name, db: d}, true
	}
	return Table{}, false
}

// Table returns the table with the given name from db, creating it empty if it
// does not exist.
func (d *Database) Table(name string) Table {
	if _, ok := d.tabs[name]; !ok {
		d.tabs[name] = make(map[string]*logEntry)
		d.addLog(&logEntry{Op: opCreateTable, A: name, TS: timeNow()})
	}
	return Table{name: name, db: d}
}

// DeleteTable deletes the specified table and reports whether it existed.
func (d *Database) DeleteTable(name string) bool {
	if _, ok := d.tabs[name]; ok {
		delete(d.tabs, name)
		d.addLog(&logEntry{Op: opDeleteTable, A: name, TS: timeNow()})
		return true
	}
	return false
}

// Rewind rewinds the state of d to the specified time, and reports whether
// this changed the visible state. If the visible state changed, the database
// is marked as modified.
//
// If the database was already rewound, it is reverted before applying the new
// rewind. After rewinding, modifications apply to the rewound state.  Use
// Revert to revert to the state prior to the most recent rewind (if any).
func (d *Database) Rewind(when time.Time) bool {
	d.Revert() // in case there was a previous rewind

	ts := when.UnixMicro()
	var newLog []*logEntry
	for _, e := range d.log {
		if e.TS > ts {
			break
		}
		newLog = append(newLog, e)
	}
	isChanged := len(newLog) < len(d.log)
	if isChanged {
		d.saved, d.wasMod, d.log = d.log, d.dirty, newLog
		d.dirty = true
		d.tabs = tablesFromLog(d.log)
		return true
	}
	return false
}

// Revert undoes the effect of the most recent Rewind. It does nothing if d has
// not been rewound.
func (d *Database) Revert() {
	if d.saved != nil {
		d.log, d.dirty, d.saved = d.saved, d.wasMod, nil
		d.tabs = tablesFromLog(d.log)
	}
}

// Time reports the timestamp of the latest state change of d.  It returns the
// zero time if the database is empty.
func (d *Database) Time() time.Time {
	if len(d.log) == 0 {
		return time.Time{}
	}
	return time.UnixMicro(d.log[len(d.log)-1].TS)
}

// Snapshot returns a map of the current state of the database.  The keys of
// the outer map are the names of the tables, the inner maps are the keys and
// values. Modifications of the snapshot do not affect the database.
func (d *Database) Snapshot() map[string]map[string]json.RawMessage {
	snap := make(map[string]map[string]json.RawMessage)
	for name, tab := range d.tabs {
		m := make(map[string]json.RawMessage)
		for key, val := range tab {
			cp := string(val.C) // don't alias the log
			m[key] = json.RawMessage(cp)
		}
		snap[name] = m
	}
	return snap
}

type wireDB struct {
	Log []*logEntry `json:"log"`
}

func (d Database) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireDB{Log: d.log})
}

func (d *Database) UnmarshalJSON(data []byte) error {
	var wdb wireDB
	if err := json.Unmarshal(data, &wdb); err != nil {
		return err
	}
	d.log = wdb.Log
	d.tabs = tablesFromLog(d.log)
	return nil
}

func newDatabase(log []*logEntry) *Database { return &Database{log: log, tabs: tablesFromLog(log)} }

func tablesFromLog(log []*logEntry) map[string]map[string]*logEntry {
	m := make(map[string]map[string]*logEntry)
	for _, e := range log {
		switch e.Op {
		case opCreateTable:
			if m[e.A] == nil {
				m[e.A] = make(map[string]*logEntry)
			}
		case opDeleteTable:
			delete(m, e.A)
		case opRenameTable:
			old := m[e.A]
			delete(m, e.A)
			m[e.B] = old
		case opClearTable:
			clear(m[e.A])
		case opUpdateKey:
			m[e.A][e.B] = e
		case opDeleteKey:
			delete(m[e.A], e.B)
		}
	}
	return m
}

func (d *Database) addLog(e *logEntry) { d.log = append(d.log, e); d.dirty = true }

type logEntry struct {
	Op string          `json:"op"`
	A  string          `json:"tab,omitempty"`
	B  string          `json:"key,omitempty"`
	C  json.RawMessage `json:"val,omitempty"`
	TS int64           `json:"clk,omitempty"`
}

// A Table is a mapping of string keys to JSON-marshalable values.
type Table struct {
	name string
	db   *Database
}

// Get reports whether t contains a record for key, and if so unmarshals its
// value into val. As a special case, if val == nil the unmarshal is skipped.
func (t Table) Get(key string, val any) bool {
	e, ok := t.db.tabs[t.name][key]
	if ok {
		if val != nil {
			unmarshalOrPanic(e.C, val)
		}
		return true
	}
	return false
}

// Get reports whether t contains a record for key, and if so returns its
// value. It returns a zero value if the key does not exist.
func Get[T any](t Table, key string) (T, bool) {
	var val T
	ok := t.Get(key, &val)
	return val, ok
}

// Keys returns a slice of the keys of t in lexicographic (sorted) order.
func (t Table) Keys() []string {
	tab := t.db.tabs[t.name]
	out := make([]string, 0, len(tab))
	for key := range tab {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// AsMap returns a map of the values of t. The resulting map is independent of
// the table, and modifications of it do not affect the table.
func AsMap[T any](t Table) map[string]T {
	tab := t.db.tabs[t.name]
	m := make(map[string]T, len(tab))
	for key, e := range tab {
		var val T
		unmarshalOrPanic(e.C, &val)
		m[key] = val
	}
	return m
}

// Set adds or updates the value of key in t and reports whether it was new.
func (t Table) Set(key string, val any) bool {
	bits, err := json.Marshal(val)
	if err != nil {
		panic(err)
	}
	tab := t.db.tabs[t.name]
	_, isOld := tab[key]
	tab[key] = &logEntry{Op: opUpdateKey, A: t.name, B: key, C: bits, TS: timeNow()}
	t.db.addLog(tab[key])
	return !isOld
}

// SetMap adds or updates the values in t to the corresponding entries from m.
func SetMap[T any](t Table, m map[string]T) {
	for key, val := range m {
		t.Set(key, val)
	}
}

// Delete removes key from t and reports whether it was present.
func (t Table) Delete(key string) bool {
	tab := t.db.tabs[t.name]
	if _, ok := tab[key]; ok {
		delete(tab, key)
		t.db.addLog(&logEntry{Op: opDeleteKey, A: t.name, B: key, TS: timeNow()})
		return true
	}
	return false
}

// Rename renames t to the specified name.
func (t *Table) Rename(newName string) {
	if t.name == newName {
		return
	}
	t.db.tabs[newName] = t.db.tabs[t.name]
	delete(t.db.tabs, t.name)
	t.db.addLog(&logEntry{Op: opRenameTable, A: t.name, B: newName, TS: timeNow()})
	t.name = newName
}

// Clear removes all the keys from t.
func (t Table) Clear() {
	tab := t.db.tabs[t.name]
	if len(tab) != 0 {
		clear(tab)
		t.db.addLog(&logEntry{Op: opClearTable, A: t.name, TS: timeNow()})
	}
}

// Len reports the number of keys in t.
func (t Table) Len() int { return len(t.db.tabs[t.name]) }

func timeNow() int64 { return time.Now().UnixMicro() }

func decryptWithKey(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialize key: %w", err)
	}
	if len(data) < aead.NonceSize() {
		return nil, errors.New("malformed input: short nonce")
	}
	nonce, ctext := data[:aead.NonceSize()], data[aead.NonceSize():]
	return aead.Open(nil, nonce, ctext, nil)
}

func encryptWithKey(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialize key: %w", err)
	}
	buf := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err := cryptorand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return aead.Seal(buf, buf, data, nil), nil
}

func unmarshalOrPanic(data []byte, v any) {
	if err := json.Unmarshal(data, v); err != nil {
		panic(err)
	}
}

func compress(data []byte) []byte { return snappy.Encode(nil, data) }

func decompress(data []byte) []byte {
	dec, err := snappy.Decode(nil, data)
	if err != nil {
		panic(err)
	}
	return dec
}
