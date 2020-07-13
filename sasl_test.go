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

func TestDigestMD5Mechanism(t *testing.T) {
	mechanism := NewDigestMD5Mechanism("user", "pass")
	client := NewSaslClient("localhost", mechanism)
	client.GetConfig().AuthorizationID = "authId"
	client.Start()
	challenge := "nonce=\"rmD6R8aMYVWH+/ih9HGBr3xNGAR6o2DUxpKlgDz6gUQ=\"," +
		"realm=\"example.org\",qop=\"auth,auth-int,auth-conf\"," +
		"cipher=\"rc4-40,rc4-56,rc4,des,3des\",maxbuf=65536," +
		"charset=utf-8,algorithm=md5-sess"
	response, _ := client.Step([]byte(challenge))
	if !client.Complete() {
		t.Fatal("Challenge should have completed")
	}

	var expected = []byte{113, 111, 112, 61, 97, 117, 116, 104, 44, 97, 117, 116, 104, 45, 105, 110, 116, 44, 97, 117, 116, 104, 45,
		99, 111, 110, 102, 44, 114, 101, 97, 108, 109, 61, 34, 101, 120, 97, 109, 112, 108, 101, 46, 111, 114, 103, 34, 44, 117, 115,
		101, 114, 110, 97, 109, 101, 61, 34, 117, 115, 101, 114, 34, 44, 110, 111, 110, 99, 101, 61, 34, 114, 109, 68, 54, 82, 56, 97,
		77, 89, 86, 87, 72, 43, 47, 105, 104, 57, 72, 71, 66, 114, 51, 120, 78, 71, 65, 82, 54, 111, 50, 68, 85, 120, 112, 75, 108,
		103, 68, 122, 54, 103, 85, 81, 61, 34, 44, 99, 110, 111, 110, 99, 101, 61, 34, 53, 53, 55, 55, 48, 48, 54, 55, 57, 49, 57, 52,
		55, 55, 55, 57, 52, 49, 48, 34, 44, 110, 99, 61, 48, 48, 48, 48, 48, 48, 48, 49, 44, 100, 105, 103, 101, 115, 116, 45, 117, 114,
		105, 61, 34, 99, 101, 114, 101, 98, 114, 111, 47, 34, 44, 114, 101, 115, 112, 111, 110, 115, 101, 61, 99, 55, 50, 98, 54, 49, 99,
		50, 56, 56, 102, 57, 50, 99, 102, 55, 56, 57, 49, 101, 48, 102, 100, 49, 98, 56, 56, 53, 56, 51, 54, 49}

	if !reflect.DeepEqual(response, expected) {
		t.Fatalf("Response expected was %x, but got %x", expected, response)
	}

	client.Dispose()
}
