package security

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestVerifyBcryptImport(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("demo1234"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := NewPasswordService("")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := ps.Verify("demo1234", string(hash))
	if err != nil || !ok {
		t.Fatalf("verify imported bcrypt: ok=%v err=%v", ok, err)
	}
	ok, err = ps.Verify("wrong-pass", string(hash))
	if err != nil || ok {
		t.Fatalf("reject wrong password: ok=%v err=%v", ok, err)
	}
}
