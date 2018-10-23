// +build !kerberos

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

func TestCramMD5Mechanism(t *testing.T) {
	mechanism := NewCramMD5Mechanism("user", "pass")
	client := NewSaslClient("localhost", mechanism)
	client.Start()
	response, _ := client.Step([]byte("msg"))
	if !client.Complete() {
		t.Fatal("Challenge should have completed")
	}

	var expected = []byte{117, 115, 101, 114, 32, 182, 240, 88, 240, 136, 183, 51, 193, 125, 1, 166, 33, 169, 193, 157, 192}

	if !reflect.DeepEqual(response, expected) {
		t.Fatalf("Response expected was %x, but got %x", expected, response)
	}

	client.Dispose()
}
