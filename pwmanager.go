package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"strings"
)

type PasswordEntry struct {
	Site     string
	Login    string
	Comment  string
	Password string
}

var (
	filePath string
)

type wrongUsageError struct{}

func (e *wrongUsageError) Error() string {
	return ""
}

func readPasswords() ([]PasswordEntry, error) {
	jsonText, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadFile(): %s", err.Error())
	}

	var passwordEntries []PasswordEntry
	err = json.Unmarshal(jsonText, &passwordEntries)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal(): %s", err.Error())
	}

	return passwordEntries, nil
}

func writePasswords(passwords []PasswordEntry) error {
	jsonText, err := json.MarshalIndent(passwords, "", "\t")

	if err != nil {
		return fmt.Errorf("json.Marshal(): %s", err.Error())
	}

	osFile, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("os.OpenFile(): %s", err.Error())
	}
	defer osFile.Close()

	_, err = osFile.Write(jsonText)
	if err != nil {
		return fmt.Errorf("(os.File) os.Write(): %s", err.Error())
	}

	return nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: pwmanager <command> [flags]

Commands are:
  add
    	adds a new password
  remove <regexp>
    	removes passwords whose site matches provided regexp
  get <regexp>
    	gets a password whose site matches provided regexp

Flags are:`)
	flag.PrintDefaults()

}

func add(args []string) error {
	var passwordEntries []PasswordEntry
	var err error

	_, err = os.Stat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		passwordEntries = make([]PasswordEntry, 0)
	} else {
		passwordEntries, err = readPasswords()
		if err != nil {
			return fmt.Errorf("readPasswords(): %s", err.Error())
		}
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Site: ")
	line, _, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("(io.Reader) bufio.ReadLine() %s", err.Error())
	}
	site := string(line)

	fmt.Printf("Login: ")
	line, _, err = reader.ReadLine()
	if err != nil {
		return fmt.Errorf("(io.Reader) bufio.ReadLine() %s", err.Error())
	}
	login := string(line)

	fmt.Printf("Comment: ")
	line, _, err = reader.ReadLine()
	if err != nil {
		return fmt.Errorf("(io.Reader) bufio.ReadLine() %s", err.Error())
	}
	comment := string(line)

	p, err := exec.Command("pwgen", "-s", "-y", "-n", "24", "1").Output()
	if err != nil {
		return fmt.Errorf("pwgen: %s", err.Error())
	}
	password := strings.TrimSpace(string(p))

	passwordEntries = append(passwordEntries, PasswordEntry{Site: site, Login: login, Comment: comment, Password: base64.StdEncoding.EncodeToString([]byte(password))})

	err = writePasswords(passwordEntries)
	if err != nil {
		return fmt.Errorf("writePasswords(): %s", err.Error())
	}

	return nil
}

func remove(args []string) error {
	if len(args) != 1 {
		return new(wrongUsageError)
	}

	passwordEntries, err := readPasswords()
	if err != nil {
		return fmt.Errorf("readPasswords(): %s", err.Error())
	}

	matchedEntries := []*PasswordEntry{}
	lastMatchedEntryIndex := -1

	for i, entry := range passwordEntries {
		matched, err := regexp.MatchString(args[0], entry.Site)
		if err != nil {
			return fmt.Errorf("regexp.MatchString(): %s", err.Error())
		}
		if matched {
			matchedEntries = append(matchedEntries, &passwordEntries[i])
			lastMatchedEntryIndex = i
		}
	}

	if len(matchedEntries) == 0 {
		return fmt.Errorf("Site not found")
	} else if len(matchedEntries) == 1 {
		// delete passwordEntries at lastMatchedEntryIndex (lets keep the order)
		newArray := make([]PasswordEntry, 0)
		newArray = append(newArray, passwordEntries[:lastMatchedEntryIndex]...)
		newArray = append(newArray, passwordEntries[lastMatchedEntryIndex+1:]...)
		passwordEntries = newArray
	} else {
		errorStr := "Multiple matches:\n"
		for _, m := range matchedEntries {
			errorStr += fmt.Sprintf("  %s\n", m.Site)
		}
		return fmt.Errorf("%s", errorStr)
	}

	err = writePasswords(passwordEntries)
	if err != nil {
		return fmt.Errorf("writePasswords(): %s", err.Error())
	}
	return nil
}

func get(args []string) error {
	if len(args) != 1 {
		return new(wrongUsageError)
	}

	passwordEntries, err := readPasswords()
	if err != nil {
		return fmt.Errorf("readPasswords(): %s", err.Error())
	}

	matchedEntries := []*PasswordEntry{}

	for i, entry := range passwordEntries {
		matched, err := regexp.MatchString(args[0], entry.Site)
		if err != nil {
			return fmt.Errorf("regexp.MatchString(): %s", err.Error())
		}
		if matched {
			matchedEntries = append(matchedEntries, &passwordEntries[i])
		}
	}

	if len(matchedEntries) == 0 {
		return fmt.Errorf("Site not found")
	} else if len(matchedEntries) == 1 {
		pw, err := base64.StdEncoding.DecodeString(matchedEntries[0].Password)
		if err != nil {
			return fmt.Errorf("base64.DecodeString(): %s", err.Error())
		}

		fmt.Printf("Site: %s\n", matchedEntries[0].Site)
		fmt.Printf("Login: %s\n", matchedEntries[0].Login)
		fmt.Printf("Comment: %s\n", matchedEntries[0].Comment)
		fmt.Printf("Password: %s\n", string(pw))

	} else {
		errorStr := "Multiple matches:\n"
		for _, m := range matchedEntries {
			errorStr += fmt.Sprintf("  %s\n", m.Site)
		}
		return fmt.Errorf("%s", errorStr)
	}

	return nil
}

func main() {
	// parse the arguments
	flag.StringVar(&filePath, "f", "",
		"Name of file that stores the passwords. Leave empty for the default $HOME/.pwmanager/passwords.json")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	// establish the default file path if needed
	if filePath == "" {
		u, err := user.Current()
		if err != nil {
			fmt.Fprintf(os.Stderr, "user.Current(): %s\n", err.Error())
			os.Exit(1)
		}

		err = os.MkdirAll(path.Join(u.HomeDir, ".pwmanager"), 0755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "os.MkdirAll: %s\n", err.Error())
			os.Exit(1)
		}

		filePath = path.Join(u.HomeDir, ".pwmanager", "passwords.json")
	}

	var err error

	// execute the commands
	if args[0] == "add" {
		err = add(args[1:])
	} else if args[0] == "remove" {
		err = remove(args[1:])
	} else if args[0] == "get" {
		err = get(args[1:])
	} else {
		printUsage()
		os.Exit(1)
	}

	// top-level error handling
	if err != nil {
		_, isWrongUsageError := err.(*wrongUsageError)
		if isWrongUsageError {
			printUsage()
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "%s(): %s\n", args[0], err.Error())
		}
		os.Exit(1)
	}
}
