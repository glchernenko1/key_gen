package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

func main() {
	sshFlag := flag.Bool("ssh", false, "Save only SSH keys")
	allFlag := flag.Bool("all", false, "Save all keys")
	helpFlag := flag.Bool("help", false, "Only show help (not save)")
	printFlag := flag.Bool("p", false, "Show AGE.private key")
	flag.Parse()

	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Println("Error: password required")
		printHelp()
		os.Exit(1)
	}
	seed := args[0]
	privateKey, publicKey, agePrivateKey, agePublicKey := generateKeys(seed)

	if *sshFlag {
		saveSSHKey(privateKey, publicKey)
		return
	}
	if *allFlag {
		saveSSHKey(privateKey, publicKey)
		saveAGEkey(agePrivateKey, agePublicKey)
		return
	}
	if *printFlag {
		fmt.Println(agePrivateKey.String())
		return
	}

	saveAGEkey(agePrivateKey, agePublicKey)

}

func printHelp() {
	fmt.Println("Usage: key_gen [options] <password>")
	fmt.Println("Options:")
	fmt.Println("  -ssh    Save only SSH keys")
	fmt.Println("  -all    Save all keys (SSH and age)")
	fmt.Println("  -p      Only Show AGE.private key (not save)")
	fmt.Println("  -help   Show help")
	fmt.Println("\nWithout options, the program saves only age keys.")
}

func saveSSHKey(privateKey []byte, publicKey ssh.PublicKey) {
	// Save SSH public key to file
	pubKeyPath := "id_ed25519.pub"
	err := os.WriteFile(pubKeyPath, ssh.MarshalAuthorizedKey(publicKey), 0644)
	if err != nil {
		fmt.Println("Error saving SSH public key:", err)
		os.Exit(1)
	}

	// Save SSH private key to file
	privKeyPath := "id_ed25519"
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: privateKey,
	})
	err = os.WriteFile(privKeyPath, privKeyPEM, 0600)
	if err != nil {
		fmt.Println("Error saving SSH private key:", err)
		os.Exit(1)
	}
	absSSHPublicKeyPath, _ := filepath.Abs(pubKeyPath)
	absSSHPrivateKeyPath, _ := filepath.Abs(privKeyPath)

	fmt.Printf("SSH public key saved to: %s\n", absSSHPublicKeyPath)
	fmt.Printf("SSH private key saved to: %s\n", absSSHPrivateKeyPath)
}

func saveAGEkey(agePrivateKey *age.X25519Identity, agePublicKey *age.X25519Recipient) {
	agePrivKeyPath := "key_age"
	err := os.WriteFile(agePrivKeyPath, []byte(agePrivateKey.String()), 0600)
	if err != nil {
		fmt.Println("Error saving age private key:", err)
		os.Exit(1)
	}

	// Save age public key to file
	agePubKeyPath := "key_age.pub"
	err = os.WriteFile(agePubKeyPath, []byte(agePublicKey.String()), 0644)
	if err != nil {
		fmt.Println("Error saving age public key:", err)
		os.Exit(1)
	}

	absAgePrivateKeyPath, _ := filepath.Abs(agePrivKeyPath)
	absAgePublicKeyPath, _ := filepath.Abs(agePubKeyPath)
	fmt.Printf("age private key saved to: %s\n", absAgePrivateKeyPath)
	fmt.Printf("age public key saved to: %s\n", absAgePublicKeyPath)
}

func generateKeys(seed string) ([]byte, ssh.PublicKey, *age.X25519Identity, *age.X25519Recipient) {
	// Generate a 32-byte seed from the input string
	hash := sha256.Sum256([]byte(seed))
	privateKey := ed25519.NewKeyFromSeed(hash[:])

	// Get the SSH public key
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		fmt.Println("Error creating SSH public key:", err)
		os.Exit(1)
	}

	// Convert the SSH private key to SSH format
	sshPrivateKey, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		fmt.Println("Error marshaling SSH private key:", err)
		os.Exit(1)
	}

	// Generate age keys
	agePrivateKey, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Println("Error generating age private key:", err)
		os.Exit(1)
	}
	agePublicKey := agePrivateKey.Recipient()

	return sshPrivateKey.Bytes, publicKey, agePrivateKey, agePublicKey
}
