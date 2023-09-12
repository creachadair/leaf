package leaf_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/creachadair/leaf"
	"github.com/creachadair/mds/slice"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRekey(t *testing.T) {
	const testKey1 = "00000000000000000000000000000000"
	const testKey2 = "11111111111111111111111111111111"

	var buf1, buf2 bytes.Buffer

	t.Run("Setup", func(t *testing.T) {
		s1, err := leaf.New([]byte(testKey1))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := s1.WriteTo(&buf1); err != nil {
			t.Fatalf("Write s1: %v", err)
		}

		s2, err := leaf.New([]byte(testKey2))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := s2.WriteTo(&buf2); err != nil {
			t.Fatalf("Write s2: %v", err)
		}
	})

	cp := bytes.NewBufferString(buf1.String())
	t.Logf("Packet: %#q", buf1.String())

	t.Run("Probe", func(t *testing.T) {
		s1, err := leaf.Open([]byte(testKey1), &buf1)
		if err != nil {
			t.Fatalf("Open s1: %v", err)
		}
		s2, err := leaf.Open([]byte(testKey2), &buf2)
		if err != nil {
			t.Fatalf("Open s2: %v", err)
		}
		diffData(t, s1.Database(), s2.Database())
	})

	t.Run("WrongKey", func(t *testing.T) {
		s, err := leaf.Open([]byte(testKey2), cp)
		if err == nil {
			t.Fatalf("Open s1: got %+v, want error", s)
		} else {
			t.Logf("Open s1: got expected error: %v", err)
		}
	})
}

func TestRoundTrip(t *testing.T) {
	const testKey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

	f, err := leaf.New([]byte(testKey))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tab := f.Database().Table("test")
	leaf.SetMap(tab, map[string]int{
		"x": 100, "y": 200, "z": 300,
	})
	tab.Set("x", 400)

	logJSON(t, "Database", f.Database())

	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}

	g, err := leaf.Open([]byte(testKey), &buf)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	diffData(t, f.Database(), g.Database())

	got := leaf.AsMap[int](g.Database().Table("test"))
	if diff := cmp.Diff(got, map[string]int{
		"x": 400, "y": 200, "z": 300,
	}); diff != "" {
		t.Errorf("Read back values (-got, +want):\n%s", diff)
	}
}

func TestSemantics(t *testing.T) {
	const testKey = "********************************"
	f, err := leaf.New([]byte(testKey))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	db := f.Database()

	// An empty file should have no tables.
	if tab, ok := db.GetTable("test"); ok {
		t.Errorf("Table test: got %v, want none", tab)
	}

	// After creating a table, it should exist.
	db.Table("test")
	if _, ok := db.GetTable("test"); !ok {
		t.Error("Table test: should exist but does not")
	}

	// If we delete a table, it should not exist anymore.
	if !db.DeleteTable("test") {
		t.Error("Delete test (1): reported false")
	}
	if tab, ok := db.GetTable("test"); ok {
		t.Errorf("Table test: got %v, want none", tab)
	}
	if db.DeleteTable("test") {
		t.Error("Delete test (2): reported true")
	}

	// A fresh table should have length zero.
	tab := db.Table("test")
	if n := tab.Len(); n != 0 {
		t.Errorf("Table len: got %d, want 0", n)
	}

	// Add some values and verify we have them.
	vals := map[string]int{"x": 1, "y": 2, "z": 3}
	leaf.SetMap(tab, vals)
	checkTab(t, tab, vals)

	// Capture a timestamp so we can revert.
	clk := db.Time()
	logJSON(t, "State after insert", db.Snapshot())

	// Delete x and verify it's gone.
	if !tab.Delete("x") {
		t.Error("Delete x (1): reported false")
	}
	if tab.Get("x", nil) {
		t.Error("Get x: reported true")
	}
	if n := tab.Len(); n != 2 {
		t.Errorf("Table len: got %d, want 2", n)
	}
	if tab.Delete("x") {
		t.Error("Delete x (2): reported true")
	}

	// Verify we can get the values out as a map.
	checkTab(t, tab, map[string]int{"y": 2, "z": 3})
	logJSON(t, "State after delete", db.Snapshot())

	// Rewind the database and verify it looks as before.
	db.Rewind(clk)
	checkTab(t, tab, vals)
	logJSON(t, "State after rewind", db.Snapshot())

	// Revert and verify it went back.
	db.Revert()
	checkTab(t, tab, map[string]int{"y": 2, "z": 3})
	logJSON(t, "State after revert", db.Snapshot())

	// Clearing a table leaves it intact, but empty.
	tab.Clear()
	if _, ok := db.GetTable("test"); !ok {
		t.Error("Table test: not found")
	}
	checkTab[any](t, tab, nil)

	logJSON(t, "Database", db)
}

func diffData(t *testing.T, got, want *leaf.Database) {
	t.Helper()
	opt := cmp.AllowUnexported(leaf.Database{})
	if diff := cmp.Diff(*got, *want, opt); diff != "" {
		t.Errorf("File mismatch (-got, +want):\n%s", diff)
	}
}

func checkTab[T any](t *testing.T, tab leaf.Table, want map[string]T) {
	t.Helper()
	opts := []cmp.Option{
		cmpopts.EquateEmpty(),
	}
	if diff := cmp.Diff(leaf.AsMap[T](tab), want, opts...); diff != "" {
		t.Errorf("AsMap (-got, +want):\n%s", diff)
	}
	wantKeys := slice.MapKeys(want)
	sort.Strings(wantKeys) // the results should be sorted
	if diff := cmp.Diff(tab.Keys(), wantKeys, opts...); diff != "" {
		t.Errorf("Keys (-got, +want):\n%s", diff)
	}
	if n := tab.Len(); n != len(want) {
		t.Errorf("Len: got %d, want %d", n, len(want))
	}
}

func logJSON(t *testing.T, msg string, v any) {
	t.Helper()
	bits, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	t.Logf("%s: %#q", msg, bits)
}
