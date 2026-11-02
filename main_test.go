package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCredentialDiagnostics(t *testing.T) {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	key := "synthetic-" + hex.EncodeToString(b)
	var output bytes.Buffer
	safeDiagnostic(&output, fmt.Sprintf("route error: https://user:%s@vendor.invalid/?api_key=%s", key, key))
	if bytes.Contains(output.Bytes(), []byte(key)) {
		t.Fatal("diagnostic output leaked credential")
	}
}
