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
	byteLength = 8
	bytesNumberInBlock = 32 // 32 * 8 = 256 bits -> real length of each block
)

func main(){
	privateKey, publicKey := GenerateKey()

	reader := bufio.NewReader(os.Stdin)
	messageToSign, _ := reader.ReadString('\n')

	signedMessage := Sign(messageToSign, privateKey)

	isVerified := Verify(signedMessage, publicKey)
	fmt.Println(isVerified)
}

// Method to generate a single block of 256 signature length. Creates a block of length 32 byte (256 bit) and fills it with random numbers
func generateBlock() (block []byte) {
	block = make([]byte, bytesNumberInBlock)
	rand.Read(block)
	return 
}

// There are two private keys, each is 256 lenght long, each block is 256 bits long (32 bytes). It means that in each block there will be 32 numbers in it. 
// Public key is hashed private key. 
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

// For signing the message we first get sha256 for the message 
// Based on the hash we iterate through each bit of the hashedMessage 
// If the bit is 0 we take block from first private key
// If 1 -> from second 
// Because go doesn't support flatMap we are iterating through the signed message again to flat the array.
// NOTE: If you see more optimal solution please take a minute and message me as an Issue or to email: guinea.pig.prog@gmail.com
func Sign(stringMessage string, privateKey [numberOfPairs][2][]byte) (signedMessage [256][]byte){
	message := []byte(stringMessage)
	hashedMessage := sha256.Sum256(message)

	complexMessage := [bytesNumberInBlock][8][]byte{}

	for i := 0; i < bytesNumberInBlock; i++ { // the length if message is 256 bit -> 32 bytes. We can iterate only byte by byte (by numbers in array). It means I have to iterate 32 times
		complexMessage[i] = getSignForNumber(hashedMessage[i], privateKey[8 * i : 8 * (i + 1)]) // В privateKey argument we have to pass privateKey 8 blocks
	}

	// flatting arrays 
	index := 0
	for i := 0; i < bytesNumberInBlock; i++ {
		for j := 0; j < 8; j++ {
			signedMessage[index] = complexMessage[i][j]
			index = index + 1
		}
	}
	return
}

// Pass the byte (we cannot actually iterate through each bit of hashedMessage) 
// Iterate with size of byte (which is always 8 and stated in constants) 
// To get desired bit shift current byte to 7 - i; Then mask the result with 00000001 so you have only the smallest bit 
// EXAMPLE: byte = 10101010
// i = 0 -> number = 00000001 & 00000001 -> number = 00000001
// i = 1 -> number = 00000010 & 00000001 -> number = 00000000
// ...
// i = 7 -> number = 10101010 & 00000001 -> number = 00000001
func getSignForNumber(message byte, block [][2][]byte) (signedBlock [8][]byte) {
	for i := 0; i < byteLength; i++ {
		number := (message >> (7 - i)) & 1
		signedBlock[i] = block[i][number]
	}
	return
}

// To verify the message (to verify that the person who claims it theirs message) we have to have the public key and the signed message. The latter is partial private key. 
// What we have to do is to iterate throught each block in signed message, hash each block and to compare with public key. There is two blocks for each public key. 
// We compare hashed message block with each block of public key. If they both are different then it is not verified. 
func Verify(signedMessage [numberOfPairs][]byte, publicKey [numberOfPairs][2][]byte) (isVerified bool){
	for i := 0; i < numberOfPairs; i++ {
		hashedBlock := sha256.Sum256(signedMessage[i])
		for j := range hashedBlock {
			if hashedBlock[j] != publicKey[i][0][j] && hashedBlock[j] != publicKey[i][1][j]{
				return false
			}
		}
	}
	return true
}
