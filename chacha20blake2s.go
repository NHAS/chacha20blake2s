package chacha20blake2s

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
)

const hmacSize = 32

type chacha20blake2s struct {
	key []byte
}

func (c *chacha20blake2s) Seal(plaintext []byte) (ciphertext []byte, err error) {

	nonce := make([]byte, chacha20.NonceSizeX, chacha20.NonceSizeX+len(plaintext)+hmacSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	//This is more or less stolen from the AEAD construction of chacha20poly1305
	var hmacKey [32]byte
	s, _ := chacha20.NewUnauthenticatedCipher(c.key, nonce)
	s.XORKeyStream(hmacKey[:], hmacKey[:])
	s.SetCounter(1) // set the counter to 1, skipping 32 bytes
	s.XORKeyStream(plaintext, plaintext)

	nonce = append(nonce, plaintext...)

	h, err := blake2s.New256(hmacKey[:])
	if err != nil {
		return nil, err
	}
	h.Write(nonce)
	hmac := h.Sum(nil)

	ciphertext = append(nonce, hmac...)

	return
}

func (c *chacha20blake2s) Open(ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < hmacSize+chacha20.NonceSizeX {
		return nil, errors.New("The input plaintext was too small")
	}

	nonce := ciphertext[:chacha20.NonceSizeX]
	hmac := ciphertext[len(ciphertext)-hmacSize:]
	ciphertext = ciphertext[:len(ciphertext)-hmacSize]

	var hmacKey [32]byte
	s, _ := chacha20.NewUnauthenticatedCipher(c.key, nonce)
	s.XORKeyStream(hmacKey[:], hmacKey[:])
	s.SetCounter(1) // set the counter to 1, skipping 32 bytes

	h, err := blake2s.New256(hmacKey[:])
	if err != nil {
		return nil, err
	}
	h.Write(ciphertext)
	expected := h.Sum(nil)

	if subtle.ConstantTimeCompare(hmac, expected) != 1 {
		return nil, errors.New("HMAC validation failed")
	}

	plaintext = make([]byte, len(ciphertext[chacha20.NonceSizeX:]))

	s.XORKeyStream(plaintext, ciphertext[chacha20.NonceSizeX:])

	return
}

func New(key []byte) (c *chacha20blake2s, err error) {
	if len(key) != chacha20.KeySize {
		return nil, errors.New("Key too small to use")
	}

	c = &chacha20blake2s{}

	c.key = key

	return
}
