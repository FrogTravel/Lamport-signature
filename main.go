package main

import(
	"fmt"
	"math/rand" 
	"crypto/sha256"
	"bufio"
	"os"
)

const (
	numberOfPairs = 256
)

func main(){
	privateKey, publicKey := GenerateKey()

	reader := bufio.NewReader(os.Stdin)
	messageToSign, _ := reader.ReadString('\n')

	signedMessage := Sign(messageToSign, privateKey)

	isVerified := Verify(signedMessage, publicKey)
	fmt.Println(isVerified)
}

func printKey(key [numberOfPairs][2][]byte){
	for i := 0; i < numberOfPairs; i++{
		fmt.Println(key[i])		
	}
}

func generateBlock() (block []byte) {
	block = make([]byte, 32)
	rand.Read(block)
	return 
}

func GenerateKey() (privateKey [numberOfPairs][2][]byte, publicKey [numberOfPairs][2][]byte) {
	for i := 0; i < numberOfPairs; i++ {
		for j := 0; j < 2; j++{
			privateKey[i][j] = generateBlock()
		}
	}

	for i := 0; i < numberOfPairs; i++ {
		for j := 0; j < 2; j++ {
			publicKey[i][j] = hashBlock(privateKey[i][j])
		}
	}

	return 
}

func hashBlock(keyToHash []byte) []byte{
	var hashedKey = sha256.Sum256(keyToHash) 
	return hashedKey[:]
}

func Sign(stringMessage string, privateKey [numberOfPairs][2][]byte) (signedMessage [256][]byte){
	message := []byte(stringMessage)
	hashedMessage := sha256.Sum256(message)

	complexMessage := [32][8][]byte{}

	for i := 0; i < 32; i++ { // длина сообщения 256 bit -> 32 byte. Я могу проходится только побайтово (по числам в массиве) Значит мне нужно пройтись 32 раза
		complexMessage[i] = getSignForNumber(hashedMessage[i], privateKey[8 * i : 8 * (i + 1)]) // В private key нужно передать privateKey[0, 8]
	}

	// flatting arrays 
	index := 0
	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			signedMessage[index] = complexMessage[i][j]
			index = index + 1
		}
	}
	return
}

func getSignForNumber(message byte, block [][2][]byte) (signedBlock [8][]byte) {
	for i := 0; i < 8; i++ {
		number := (message >> (7 - i)) & 1
		signedBlock[i] = block[i][number]
	}
	return
}

func Verify(signedMessage [256][]byte, publicKey [numberOfPairs][2][]byte) (isVerified bool){
	for i := 0; i < 256; i++ {
		_hashedBlock := sha256.Sum256(signedMessage[i])
		hashedBlock := _hashedBlock[:]
		for j := range hashedBlock {
			if hashedBlock[j] != publicKey[i][0][j] && hashedBlock[j] != publicKey[i][1][j]{
				return false
			}
		}
	}
	return true
}
