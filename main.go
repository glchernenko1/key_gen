package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) >= 2 {
		fmt.Println("Использование: key_gen <pass>")
		os.Exit(1)
	}

	seed := os.Args[1]
	privateKey, publicKey, agePrivateKey, agePublicKey := generateKeys(seed)

	// Сохранение SSH открытого ключа в файл
	pubKeyPath := "id_ed25519.pub"
	err := os.WriteFile(pubKeyPath, ssh.MarshalAuthorizedKey(publicKey), 0644)
	if err != nil {
		fmt.Println("Ошибка при сохранении SSH открытого ключа:", err)
		os.Exit(1)
	}

	// Сохранение SSH закрытого ключа в файл
	privKeyPath := "id_ed25519"
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: privateKey,
	})
	err = os.WriteFile(privKeyPath, privKeyPEM, 0600)
	if err != nil {
		fmt.Println("Ошибка при сохранении SSH закрытого ключа:", err)
		os.Exit(1)
	}

	// Сохранение age закрытого ключа в файл
	agePrivKeyPath := "key_age"
	err = os.WriteFile(agePrivKeyPath, []byte(agePrivateKey.String()), 0600)
	if err != nil {
		fmt.Println("Ошибка при сохранении age закрытого ключа:", err)
		os.Exit(1)
	}

	// Сохранение age открытого ключа в файл
	agePubKeyPath := "key_age.pub"
	err = os.WriteFile(agePubKeyPath, []byte(agePublicKey.String()), 0644)
	if err != nil {
		fmt.Println("Ошибка при сохранении age открытого ключа:", err)
		os.Exit(1)
	}

	// Вывод информации о сохраненных файлах
	absSSHPublicKeyPath, _ := filepath.Abs(pubKeyPath)
	absSSHPrivateKeyPath, _ := filepath.Abs(privKeyPath)
	absAgePrivateKeyPath, _ := filepath.Abs(agePrivKeyPath)
	absAgePublicKeyPath, _ := filepath.Abs(agePubKeyPath)
	fmt.Printf("SSH открытый ключ сохранен в: %s\n", absSSHPublicKeyPath)
	fmt.Printf("SSH закрытый ключ сохранен в: %s\n", absSSHPrivateKeyPath)
	fmt.Printf("age закрытый ключ сохранен в: %s\n", absAgePrivateKeyPath)
	fmt.Printf("age открытый ключ сохранен в: %s\n", absAgePublicKeyPath)
}

func saveFile(name string) {

}

func generateKeys(seed string) ([]byte, ssh.PublicKey, *age.X25519Identity, *age.X25519Recipient) {
	// Генерация 32-байтового семени из входной строки
	hash := sha256.Sum256([]byte(seed))
	privateKey := ed25519.NewKeyFromSeed(hash[:])

	// Получение SSH открытого ключа
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		fmt.Println("Ошибка при создании SSH открытого ключа:", err)
		os.Exit(1)
	}

	// Преобразование SSH закрытого ключа в формат SSH
	sshPrivateKey, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		fmt.Println("Ошибка при маршалинге SSH закрытого ключа:", err)
		os.Exit(1)
	}

	// Генерация age ключей
	agePrivateKey, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Println("Ошибка при генерации age закрытого ключа:", err)
		os.Exit(1)
	}
	agePublicKey := agePrivateKey.Recipient()

	return sshPrivateKey.Bytes, publicKey, agePrivateKey, agePublicKey
}
