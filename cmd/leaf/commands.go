package main

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/command"
	"github.com/creachadair/leaf"
)

func runCreate(env *command.Env) error {
	if settings.FilePath == "" {
		return env.Usagef("no file path is defined")
	} else if _, err := os.Lstat(settings.FilePath); err == nil {
		return fmt.Errorf("file %q already exists", settings.FilePath)
	}
	_, err := openFile(true)
	if err == nil {
		fmt.Fprintf(env, "created %q\n", settings.FilePath)
	}
	return err
}

func runGet(env *command.Env, table, key string) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	tab, ok := f.Database().GetTable(table)
	if !ok {
		fmt.Fprintf(env, "table not found: %q\n", table)
		return nil
	}
	var val json.RawMessage
	if !tab.Get(key, &val) {
		fmt.Fprintf(env, "key not found: %q\n", key)
		return nil
	}
	fmt.Println(string(val))
	return nil
}

func runSet(env *command.Env, table, key, value string) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	var enc any
	if json.Valid([]byte(value)) {
		enc = json.RawMessage(value)
	} else {
		enc = value // just the string
	}

	f.Database().Table(table).Set(key, enc)
	if f.IsModified() {
		return saveFile(f)
	}
	return nil
}

func runList(env *command.Env, table string) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	for _, key := range f.Database().Table(table).Keys() {
		fmt.Println(key)
	}
	return nil
}

func runDelete(env *command.Env, table, key string) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	tab, ok := f.Database().GetTable(table)
	if !ok {
		fmt.Fprintf(env, "table not found: %q\n", table)
	} else if tab.Delete(key) {
		fmt.Fprintf(env, "deleted: %q\n", key)
		return saveFile(f)
	}
	return nil
}

func runTableList(env *command.Env) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	for _, tab := range f.Database().TableNames() {
		fmt.Println(tab)
	}
	return nil
}

func runTableCreate(env *command.Env, name string) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	f.Database().Table(name)
	if f.IsModified() {
		fmt.Fprintf(env, "created %q\n", name)
		return saveFile(f)
	}
	return nil
}

func runTableDelete(env *command.Env, name string) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	if f.Database().DeleteTable(name) {
		fmt.Fprintf(env, "deleted %q\n", name)
		return saveFile(f)
	}
	return nil
}

func runDebugLog(env *command.Env) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	return writePrettyJSON(f.Database())
}

func runDebugSnapshot(env *command.Env) error {
	f, err := openFile(false)
	if err != nil {
		return err
	}
	return writePrettyJSON(f.Database().Snapshot())
}

var rewindFlags struct {
	Replace bool `flag:"replace,Replace the file with the rewound state (UNSAFE)"`
}

func runDebugRewind(env *command.Env, when string) error {
	ts, err := time.Parse(time.RFC3339Nano, when)
	if err != nil {
		v, err := strconv.ParseInt(when, 10, 64)
		if err != nil {
			return env.Usagef("invalid timestamp format: %q", when)
		}
		ts = time.UnixMicro(v)
	}
	f, err := openFile(false)
	if err != nil {
		return err
	}
	f.Database().Rewind(ts)
	fmt.Fprintf(env, "Rewound database to %s (%d)\n", ts.Format(time.RFC3339), ts.UnixMicro())
	if rewindFlags.Replace {
		if f.IsModified() {
			return saveFile(f)
		}
		return nil
	}
	return writePrettyJSON(f.Database().Snapshot())
}

var keyFileFlags struct {
	Random bool `flag:"random,Generate a random key"`
}

func runDebugKeyFile(env *command.Env, keyFile string) error {
	var accessKey []byte
	if keyFileFlags.Random {
		accessKey = make([]byte, leaf.AccessKeyLen)
		if _, err := cryptorand.Read(accessKey); err != nil {
			return err
		}
		fmt.Fprintf(env, "Generated a random %d-byte key\n", len(accessKey))
	} else if ak, err := promptAccessKey("", true); err != nil {
		return err
	} else {
		accessKey = ak
	}
	return atomicfile.WriteData(keyFile, accessKey, 0600)
}
