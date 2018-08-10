package gosasl

import (
	"fmt"
	"reflect"
	"testing"
)

func TestAnonymousMechanism(t *testing.T) {
	mechanism := NewAnonymousMechanism()
	client := NewSaslClient("localhost", mechanism)
	client.Start()
	ret, _ := client.Step(nil)
	if !reflect.DeepEqual(ret, []byte("Anonymous, None")) {
		t.Fatal("Unexpected response from client.process")
	}
	if !client.Complete() {
		t.Fatal("Challenge should have completed")
	}
	client.Dispose()
}

func TestPlainMechanism(t *testing.T) {
	mechanism := NewPlainMechanism("user", "password")
	client := NewSaslClient("localhost", mechanism)
	client.Start()
	response, _ := client.Step([]byte("abcd"))
	if !client.Complete() {
		t.Fatal("Challenge should have completed")
	}

	NULL := "\x00"
	expectedResponse := []byte(fmt.Sprintf("%s%s%s%s", NULL, "user", NULL, "password"))
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Fatal("Unexpected response from client.process")
	}
	client.Dispose()
}

func TestPlainMechanismWithAuthorizationId(t *testing.T) {
	mechanism := NewPlainMechanism("user", "password")
	client := NewSaslClient("localhost", mechanism)
	client.GetConfig().AuthorizationID = "authId"
	client.Start()
	response, _ := client.Step([]byte("abcd"))
	if !client.Complete() {
		t.Fatal("Challenge should have completed")
	}

	NULL := "\x00"
	expectedResponse := []byte(fmt.Sprintf("%s%s%s%s%s", "authId", NULL, "user", NULL, "password"))
	if !reflect.DeepEqual(response, expectedResponse) {
		t.Fatal("Unexpected response from client.process")
	}
	client.Dispose()
}

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
