package chacha20blake2s

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func TestTrunc(t *testing.T) {

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c1.Seal([]byte("Hello world!"))
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := c1.Seal([]byte("Test"))
	if err != nil {
		t.Fatal(err)
	}

	ct2 = ct2[:4]

	_, err = c1.Open(ct2)
	if err == nil {
		t.Fatal(err)
	}
}

func TestCheckHMACMalliable(t *testing.T) {

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c1.Seal([]byte("Hello world!"))
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := c1.Seal([]byte("Test"))
	if err != nil {
		t.Fatal(err)
	}

	ct2[len(ct2)-1] = ct2[len(ct2)-1] + 1

	_, err = c1.Open(ct2)
	if err == nil {
		t.Fatal(err)
	}

}

func TestCheckNonceMalliable(t *testing.T) {

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c1.Seal([]byte("Hello world!"))
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := c1.Seal([]byte("Test"))
	if err != nil {
		t.Fatal(err)
	}

	ct2[0] = ct2[0] + 1

	_, err = c1.Open(ct2)
	if err == nil {
		t.Fatal(err)
	}

}

func TestCheckCiphertextMalliable(t *testing.T) {

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c1.Seal([]byte("Hello world!"))
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := c1.Seal([]byte("Test"))
	if err != nil {
		t.Fatal(err)
	}

	ct2[chacha20.NonceSizeX+1] = ct2[chacha20.NonceSizeX+1] + 1

	_, err = c1.Open(ct2)
	if err == nil {
		t.Fatal(err)
	}

}

func TestEasyDecryption(t *testing.T) {

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c1.Seal([]byte("Hello world!"))
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := c1.Seal([]byte("Test"))
	if err != nil {
		t.Fatal(err)
	}

	pt, err := c1.Open(ct2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, []byte("Test")) {
		t.Fatal("Input and output did not match")
	}
}
