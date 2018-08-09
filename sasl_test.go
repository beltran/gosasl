package gosasl

import (
	"testing"
	"reflect"
	"fmt"
)

func TestClient(t *testing.T) {
	client := NewSaslClient("localhost", "Anonymous", "", "")
	ret, _ := client.Step(nil)
	if !reflect.DeepEqual(ret , []byte("Anonymous, None")) {
		t.Fatal("Unexpected response from client.process")
	}
}

func TestAnonymousMechanism(t *testing.T) {
	mechanism := NewAnonymousMechanism()
	ret, _ := mechanism.step(nil)
	if !reflect.DeepEqual(ret , []byte("Anonymous, None")) {
		t.Fatal("Unexpected response from mechanism.process")
	}
}

func TestPlainMechanism(t *testing.T) {
	client := NewSaslClient("localhost", "PLAIN", "user", "password")
	response, _ := client.Step([]byte("abcd"))
	if (!client.Complete()) {
		t.Fatal("Challenge should have completed")
	}

	NULL := "\x00"
	expectedResponse := []byte(fmt.Sprintf("%s%s%s%s", NULL, "user", NULL, "password"))
	if !reflect.DeepEqual(response , expectedResponse) {
		t.Fatal("Unexpected response from client.process")
	}
	client.Dispose()
}

func TestGSSAPIMechanism(t *testing.T) {
	mechanism, err := NewGSSAPIMechanism("localhost", "hs2.example.com", "hive")

	if err != nil {
		t.Fatal(err)
	}

	client := NewSaslClientWithMechanism("localhost", mechanism)

	for _, input := range [][]byte{[]byte("Ahjdskahdjkaw12kadlsj"), []byte("0"), nil} {
		client.Step(input)
	}

	if client.Complete() {
		t.Fatal("Client can't be complete")
	}

	client.Dispose()
}
