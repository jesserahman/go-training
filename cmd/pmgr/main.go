package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type Account struct {
	Username string `json:"name"`
	Password []byte `json:"password"`
}

type Vault struct {
	Accounts []Account `json:"account"`
}

func main() {
	filename := "userData.json"
	hashedPassphrase := createHash("p@S$w0rd")
	runCommandLineProgram(filename, hashedPassphrase)
}

func runCommandLineProgram(filename string, hashedPassphrase string) {
	addHelperFlagText()

	// create new vault with existing data
	mainVault := Vault{}
	dataFile, error := ioutil.ReadFile(filename)
	if error != nil {
		fmt.Println("unable to read file")
		os.Exit(1)
	}
	error = json.Unmarshal([]byte(dataFile), &mainVault)
	if error != nil {
		fmt.Println("unable to populate vault")
		os.Exit(1)
	}

	vaultChanged := false
	switch os.Args[1] {
	case "add":
		validateCommandLineArguments(3)
		mainVault.addUserEntryToVault(os.Args[2], os.Args[3], hashedPassphrase)
		vaultChanged = true
	case "get":
		validateCommandLineArguments(2)
		mainVault.getPasswordFromVault(os.Args[2], hashedPassphrase)
	case "update":
		validateCommandLineArguments(3)
		(&mainVault).updatePasswordInVault(os.Args[2], os.Args[3], hashedPassphrase)
		vaultChanged = true
	case "delete":
		validateCommandLineArguments(2)
		(&mainVault).deleteUserEntryFromVault(os.Args[2])
		vaultChanged = true
	default:
		fmt.Printf("You entered an invalid option")
	}

	// send any changes back to data file
	if vaultChanged {
		fmt.Println("updating json")
		updateJsonFile(mainVault, filename)
	}
}

// *** main functions
func addHelperFlagText() {
	boolArgPtr := flag.Bool("help", false, "Give instructions on how to use the program")
	flag.Parse()

	if *boolArgPtr {
		fmt.Println("Welcome to password manager!")
		fmt.Println("To create a new username and password use: $ go run main.go add {username} {password}")
		fmt.Println("To retrieve your password use: $ go run main.go get {username}")
		fmt.Println("To update your password use: $ go run main.go update {username} {newPassword}")
		fmt.Println("To delete your username and password use: $ go run main.go delete {username}")
		os.Exit(1)
	}
}

func validateCommandLineArguments(expectedArgumentCount int) {
	expectedLengthExcludingFilePath := expectedArgumentCount+1
	if len(os.Args) !=  expectedLengthExcludingFilePath{
		errorMessage := fmt.Sprintf("Wrong number of arguments: expected %v, got %v", expectedLengthExcludingFilePath-1, len(os.Args)-1)
		fmt.Println(errorMessage)
		os.Exit(1)
	}
}

func (mainVault *Vault) isUserInVault(username string) bool {
	found := false
	for _, v := range mainVault.Accounts {
		if v.Username == username {
			found = true
		}
	}
	return found
}

func (mainVault *Vault) addUserEntryToVault(username string, password string, hashedPassphrase string) {
	if mainVault.isUserInVault(username) {
		fmt.Println("Oops! Looks like this account already exists")
		os.Exit(1)
	}

	//encrypt new password
	encryptedPasswordAsByteSlice := encrypt([]byte(password), hashedPassphrase)

	// create new account entry
	newAccount := Account{Username: username, Password: encryptedPasswordAsByteSlice}
	mainVault.Accounts = append(mainVault.Accounts, newAccount)
	fmt.Println("User added to Vault")
}

func (mainVault *Vault) getPasswordFromVault(username string, hashedPassphrase string) string {
	if !mainVault.isUserInVault(username) {
		fmt.Println("Oops! Looks like that username doesn't exist")
		os.Exit(1)
	}

	for _, v := range mainVault.Accounts {
		if v.Username == username {
			fmt.Println("password: ", string(decrypt(v.Password, hashedPassphrase)))
		}
	}

	successMessage := "successfully retrieved password"
	fmt.Println(successMessage)
	return successMessage
}

func (mainVault *Vault) updatePasswordInVault(username string, newPassword string, hashedPassphrase string) string {
	if !mainVault.isUserInVault(username) {
		fmt.Println("Oops! Looks like that username doesn't exist")
		os.Exit(1)
	}

	newVault := Vault{}
	encryptedPasswordAsByteSlice := encrypt([]byte(newPassword), hashedPassphrase)
	for _, v := range mainVault.Accounts {
		if v.Username == username {
			newVault.Accounts = append(newVault.Accounts, Account{Username: v.Username, Password: encryptedPasswordAsByteSlice})
		} else {
			newVault.Accounts = append(newVault.Accounts, Account{Username: v.Username, Password: v.Password})
		}
	}

	*mainVault = newVault
	successMessage := "successfully updated"
	fmt.Println(successMessage)
	return successMessage
}

func (mainVault *Vault) deleteUserEntryFromVault(username string) string {
	if !mainVault.isUserInVault(username) {
		fmt.Println("Oops! Looks like that username doesn't exist")
		os.Exit(1)
	}

	newVault := Vault{}

	for _, v := range mainVault.Accounts {
		if v.Username != username {
			newVault.Accounts = append(newVault.Accounts, Account{Username: v.Username, Password: v.Password})
		}
	}

	*mainVault = newVault
	successMessage := "successfully deleted"
	fmt.Println(successMessage)
	return successMessage
}

// **** Helper functions
func updateJsonFile(newVault Vault, filename string) {
	// update json file with new data
	out, error := json.MarshalIndent(newVault, "", " ")

	if error != nil {
		fmt.Println(error)
	}

	error = ioutil.WriteFile(filename, out, 0644)
	if error != nil {
		fmt.Println(error)
	}
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}
