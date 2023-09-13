// Program leaf is a command-line interface to read and write LEAF files.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/getpass"
	"github.com/creachadair/leaf"
	"golang.org/x/crypto/hkdf"
)

var settings struct {
	FilePath      string `flag:"f,default=$LEAF_FILE,LEAF file path (required)"`
	AccessKeyFile string `flag:"access-key,Access key file path"`
}

func main() {
	root := &command.C{
		Name:     filepath.Base(os.Args[0]),
		Usage:    "command [args]\nhelp [command]",
		Help:     `Read and write LEAF files.`,
		SetFlags: command.Flags(flax.MustBind, &settings),

		Commands: []*command.C{
			{
				Name: "create",
				Help: "Create an empty LEAF file.",
				Run:  command.Adapt(runCreate),
			},
			{
				Name:  "get",
				Usage: "<table-name> <key>",
				Help:  "Get the value of a key.",
				Run:   command.Adapt(runGet),
			},
			{
				Name:  "set",
				Usage: "<table-name> <key> <value>",
				Help:  "Set the value of a key.",
				Run:   command.Adapt(runSet),
			},
			{
				Name:  "delete",
				Usage: "<table-name> <key>",
				Help:  "Delete a key from a table.",
				Run:   command.Adapt(runDelete),
			},
			{
				Name:  "list",
				Usage: "<table-name>",
				Help:  "List the keys in a table.",
				Run:   command.Adapt(runList),
			},
			{
				Name: "table",
				Help: "Commands to manipulate tables.",

				Commands: []*command.C{
					{
						Name: "list",
						Help: "List the known tables.",
						Run:  command.Adapt(runTableList),
					},
					{
						Name:  "create",
						Usage: "<table-name>",
						Help:  "Create a table.",
						Run:   command.Adapt(runTableCreate),
					},
					{
						Name:  "delete",
						Usage: "<table-name>",
						Help:  "Delete a table.",
						Run:   command.Adapt(runTableDelete),
					},
				},
			},
			{
				Name: "debug",
				Help: "Commands for debugging.",

				Commands: []*command.C{
					{
						Name: "log",
						Help: "Write the database log in plaintext.",
						Run:  command.Adapt(runDebugLog),
					},
					{
						Name: "snapshot",
						Help: "Print a database snapshot.",
						Run:  command.Adapt(runDebugSnapshot),
					},
					{
						Name:  "rewind",
						Usage: "<timestamp>|<rfc3339>",
						Help: `Rewind the database to this timestamp.

By default, a snapshot of the rewound database is printed.

WARNING: With --replace, the rewound database is written back to the file (destructive).
         Make a copy first if you want to keep the original.`,

						SetFlags: command.Flags(flax.MustBind, &rewindFlags),
						Run:      command.Adapt(runDebugRewind),
					},
					{
						Name:  "key-file",
						Usage: "<key-file-path>",
						Help:  "Create an access key file.",
						Run:   command.Adapt(runDebugKeyFile),
					},
				},
			},
			command.HelpCommand(nil),
		},
	}
	command.RunOrFail(root.NewEnv(nil).MergeFlags(true), os.Args[1:])
}

func getAccessKey(path string, confirm bool) ([]byte, error) {
	if settings.AccessKeyFile != "" {
		return os.ReadFile(settings.AccessKeyFile)
	}
	return promptAccessKey(path, confirm)
}

// prompt AccessKey prompts the user for a passphrase and uses it to generate
// an access key. If confirm == true, the user is required to enter the same
// passphrase twice to confirm, and an error is reported if they do not match.
func promptAccessKey(path string, confirm bool) ([]byte, error) {
	prompt := "Passphrase: "
	if path != "" {
		prompt = fmt.Sprintf("Passphrase for %s: ", filepath.Base(path))
	}
	pw, err := getpass.Prompt(prompt)
	if err != nil {
		return nil, fmt.Errorf("passphrase: %w", err)
	}
	if confirm {
		cf, err := getpass.Prompt("Confirm: ")
		if err != nil {
			return nil, fmt.Errorf("confirmation: %w", err)
		} else if cf != pw {
			return nil, errors.New("passphrases do not match")
		}
	}

	const kdfSalt = "c2V0ZWMgYXN0cm9ub215"
	kg := hkdf.New(sha256.New, []byte(pw), []byte(kdfSalt), nil)

	accessKey := make([]byte, leaf.AccessKeyLen)
	if _, err := kg.Read(accessKey); err != nil {
		return nil, fmt.Errorf("access key: %w", err)
	}
	return accessKey, nil
}

func saveFile(f *leaf.File) error {
	if settings.FilePath == "" {
		return errors.New("no file path is defined")
	}
	return atomicfile.Tx(settings.FilePath, 0600, func(af *atomicfile.File) error {
		_, err := f.WriteTo(af)
		return err
	})
}

func openFile(create bool) (*leaf.File, error) {
	if settings.FilePath == "" {
		return nil, errors.New("no file path is defined")
	}
	f, err := os.Open(settings.FilePath)
	if errors.Is(err, fs.ErrNotExist) && create {
		accessKey, err := getAccessKey(settings.FilePath, true)
		if err != nil {
			return nil, err
		}
		lf, err := leaf.New(accessKey)
		if err != nil {
			return nil, err
		}
		if err := saveFile(lf); err != nil {
			return nil, err
		}
		return lf, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	accessKey, err := getAccessKey(settings.FilePath, false)
	if err != nil {
		return nil, err
	}
	return leaf.Open(accessKey, f)
}

func writePrettyJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
