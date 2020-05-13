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

	if client.Complete() {
		t.Fatal("Client can't be complete")
	}

	client.Dispose()
}
