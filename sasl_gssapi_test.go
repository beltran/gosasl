// +build kerberos

package gosasl

import (
	"testing"
)

func TestGSSAPIMechanism(t *testing.T) {
	mechanism, err := NewGSSAPIMechanism("hive")

	if err != nil {
		t.Fatal(err)
	}

	client := NewSaslClient("localhost", mechanism)
	client.GetConfig().AuthorizationID = "username"
	client.Start()
	for _, input := range [][]byte{[]byte("Ahjdskahdjkaw12kadlsj"), []byte("0"), nil} {
		client.Step(input)
	}

	if client.Complete() {
		t.Fatal("Client can't be complete")
	}

	client.Dispose()
}
