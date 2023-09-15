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
	f := env.Config.(*leaf.File)
	tab, ok := f.Database().GetTable(table)
	if !ok {
		return fmt.Errorf("table %q not found", table)
	}
	var val json.RawMessage
	if !tab.Get(key, &val) {
		return fmt.Errorf("key %q not found", key)
	}
	fmt.Println(string(val))
	return nil
}

func runSet(env *command.Env, table, key, value string, rest ...string) error {
	if len(rest)%2 != 0 {
		return env.Usagef("odd-length key-value list: %q", rest)
	}
	f := env.Config.(*leaf.File)
	tab := f.Database().Table(table)
	all := append([]string{key, value}, rest...)

	for i := 0; i+1 < len(all); i += 2 {
		k, v := all[i], all[i+1]

		var enc any
		if json.Valid([]byte(v)) {
			enc = json.RawMessage(v)
		} else {
			enc = v // just the string
		}
		tab.Set(k, enc)
	}
	if f.IsModified() {
		return saveFile(f)
	}
	return nil
}

func runList(env *command.Env, table string) error {
	f := env.Config.(*leaf.File)
	for _, key := range f.Database().Table(table).Keys() {
		fmt.Println(key)
	}
	return nil
}

func runDelete(env *command.Env, table string, keys ...string) error {
	if len(keys) == 0 {
		return env.Usagef("missing required key")
	}
	f := env.Config.(*leaf.File)
	tab, ok := f.Database().GetTable(table)
	if !ok {
		return fmt.Errorf("table %q not found", table)
	}
	for _, key := range keys {
		if tab.Delete(key) {
			fmt.Fprintf(env, "deleted: %q\n", key)
		}
	}
	if f.IsModified() {
		return saveFile(f)
	}
	return nil
}

func runTableList(env *command.Env) error {
	f := env.Config.(*leaf.File)
	for _, tab := range f.Database().TableNames() {
		fmt.Println(tab)
	}
	return nil
}

func runTableCreate(env *command.Env, name string) error {
	f := env.Config.(*leaf.File)
	f.Database().Table(name)
	if f.IsModified() {
		fmt.Fprintf(env, "created %q\n", name)
		return saveFile(f)
	}
	return nil
}

func runTableDelete(env *command.Env, name string) error {
	f := env.Config.(*leaf.File)
	if !f.Database().DeleteTable(name) {
		return fmt.Errorf("table %q not found", name)
	}
	fmt.Fprintf(env, "deleted %q\n", name)
	return saveFile(f)
}

func runTableRename(env *command.Env, oldName, newName string) error {
	f := env.Config.(*leaf.File)
	tab, ok := f.Database().GetTable(oldName)
	if !ok {
		return fmt.Errorf("table %q not found", oldName)
	}
	tab.Rename(newName)
	if f.IsModified() {
		return saveFile(f)
	}
	return nil
}

func runDebugLog(env *command.Env) error {
	f := env.Config.(*leaf.File)
	return writePrettyJSON(f.Database())
}

func runDebugSnapshot(env *command.Env) error {
	f := env.Config.(*leaf.File)
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

	f := env.Config.(*leaf.File)
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
