// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cpace_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"filippo.io/cpace"
	"github.com/gtank/ristretto255"
)

func Example() {
	password := "password"
	c := cpace.NewContextInfo("192.0.2.1:12345", "192.0.2.2:42", nil)

	msgA, s, err := cpace.Start(password, c)
	if err != nil {
		panic(err)
	}

	msgB, keyB, err := cpace.Exchange(password, c, msgA)
	if err != nil {
		panic(err)
	}

	keyA, err := s.Finish(msgB)
	if err != nil {
		panic(err)
	}

	fmt.Println("keyA == keyB:", bytes.Equal(keyA, keyB))
	// Output: keyA == keyB: true
}

func BenchmarkStart(b *testing.B) {
	password := "password"
	c := cpace.NewContextInfo("192.0.2.1:12345", "192.0.2.2:42", []byte("ad"))

	for i := 0; i < b.N; i++ {
		msgA, s, err := cpace.Start(password, c)
		if len(msgA) != 16+32 || s == nil || err != nil {
			panic(err)
		}
	}
}

func BenchmarkExchange(b *testing.B) {
	password := "password"
	c := cpace.NewContextInfo("192.0.2.1:12345", "192.0.2.2:42", []byte("ad"))

	msgA, _, err := cpace.Start(password, c)
	if err != nil {
		panic(err)
	}

	for i := 0; i < b.N; i++ {
		msgB, key, err := cpace.Exchange(password, c, msgA)
		if len(msgB) != 32 || len(key) != 64 || err != nil {
			panic(err)
		}
	}
}

func BenchmarkFinish(b *testing.B) {
	password := "password"
	c := cpace.NewContextInfo("192.0.2.1:12345", "192.0.2.2:42", []byte("ad"))

	msgA, s, err := cpace.Start(password, c)
	if err != nil {
		panic(err)
	}

	msgB, _, err := cpace.Exchange(password, c, msgA)
	if err != nil {
		panic(err)
	}

	for i := 0; i < b.N; i++ {
		key, err := s.Finish(msgB)
		if len(key) != 64 || err != nil {
			panic(err)
		}
	}
}

func TestLargeContextValues(t *testing.T) {
	password := "password"
	validC := cpace.NewContextInfo(strings.Repeat("a", 1<<16-1), "b", nil)
	badC := cpace.NewContextInfo(strings.Repeat("a", 1<<16), "b", nil)

	msgA, _, err := cpace.Start(password, validC)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cpace.Exchange(password, validC, msgA); err != nil {
		t.Fatal(err)
	}

	if _, _, err := cpace.Start(password, badC); err == nil {
		t.Error("expected error for long context value")
	}
	if _, _, err := cpace.Exchange(password, badC, msgA); err == nil {
		t.Error("expected error for long context value")
	}
}

func TestBrokenMessages(t *testing.T) {
	password := "password"
	c := cpace.NewContextInfo("192.0.2.1:12345", "192.0.2.2:42", nil)

	msgA, s, err := cpace.Start(password, c)
	if err != nil {
		t.Fatal(err)
	}

	if _, key, err := cpace.Exchange(password, c, msgA[:len(msgA)-1]); err == nil {
		t.Error("expected error for short msgA")
	} else if key != nil {
		t.Error("on error, key was not nil")
	}
	msgA[len(msgA)-1] ^= 0xff
	if _, key, err := cpace.Exchange(password, c, msgA[:len(msgA)-1]); err == nil {
		t.Error("expected error for modified msgA")
	} else if key != nil {
		t.Error("on error, key was not nil")
	}
	msgA[len(msgA)-1] ^= 0xff

	msgB, _, err := cpace.Exchange(password, c, msgA)
	if err != nil {
		t.Fatal(err)
	}

	if key, err := s.Finish(msgB[:len(msgB)-1]); err == nil {
		t.Error("expected error for short msgB")
	} else if key != nil {
		t.Error("on error, key was not nil")
	}
	msgB[len(msgB)-1] ^= 0xff
	if key, err := s.Finish(msgB[:len(msgB)-1]); err == nil {
		t.Error("expected error for modified msgB")
	} else if key != nil {
		t.Error("on error, key was not nil")
	}
	msgB[len(msgB)-1] ^= 0xff
}

func TestResults(t *testing.T) {
	tests := []struct {
		Name                 string
		PasswordA, PasswordB string
		ContextA, ContextB   *cpace.ContextInfo
		Equal                bool
	}{
		{
			Name: "valid, without ad", Equal: true,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "b", nil),
			ContextB: cpace.NewContextInfo("a", "b", nil),
		},
		{
			Name: "valid, with ad", Equal: true,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "b", []byte("x")),
			ContextB: cpace.NewContextInfo("a", "b", []byte("x")),
		},
		{
			Name: "valid, equal identities", Equal: true,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "a", nil),
			ContextB: cpace.NewContextInfo("a", "a", nil),
		},
		{
			Name: "different passwords", Equal: false,
			PasswordA: "p", PasswordB: "P",
			ContextA: cpace.NewContextInfo("a", "b", nil),
			ContextB: cpace.NewContextInfo("a", "b", nil),
		},
		{
			Name: "different identity a", Equal: false,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "b", nil),
			ContextB: cpace.NewContextInfo("x", "b", nil),
		},
		{
			Name: "different identity b", Equal: false,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "b", nil),
			ContextB: cpace.NewContextInfo("a", "x", nil),
		},
		{
			Name: "different ad", Equal: false,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "b", []byte("foo")),
			ContextB: cpace.NewContextInfo("a", "b", []byte("bar")),
		},
		{
			Name: "swapped identities", Equal: false,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "b", nil),
			ContextB: cpace.NewContextInfo("b", "a", nil),
		},
		{
			Name: "missing ad", Equal: false,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("a", "b", []byte("x")),
			ContextB: cpace.NewContextInfo("a", "b", nil),
		},
		{
			Name: "identity concatenation", Equal: false,
			PasswordA: "p", PasswordB: "p",
			ContextA: cpace.NewContextInfo("ax", "b", nil),
			ContextB: cpace.NewContextInfo("a", "xb", nil),
		},
		{
			Name: "empty password", Equal: false,
			PasswordA: "p", PasswordB: "",
			ContextA: cpace.NewContextInfo("a", "b", nil),
			ContextB: cpace.NewContextInfo("a", "b", nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			msgA, s, err := cpace.Start(tt.PasswordA, tt.ContextA)
			if err != nil {
				t.Fatal(err)
			}
			msgB, keyB, err := cpace.Exchange(tt.PasswordB, tt.ContextB, msgA)
			if err != nil {
				t.Fatal(err)
			}
			keyA, err := s.Finish(msgB)
			if err != nil {
				t.Fatal(err)
			}

			if len(keyA) != 64 {
				t.Errorf("expected keyA length to be %v, got %v", 64, len(keyA))
			}
			if len(keyB) != 64 {
				t.Errorf("expected keyB length to be %v, got %v", 64, len(keyB))
			}

			if eq := bytes.Equal(keyA, keyB); eq != tt.Equal {
				t.Errorf("expected keyA == keyB to be %v, got %v", tt.Equal, eq)
			}
		})
	}
}

func TestIdentity(t *testing.T) {
	password := "password"
	c := cpace.NewContextInfo("192.0.2.1:12345", "192.0.2.2:42", nil)

	msgA, s, err := cpace.Start(password, c)
	if err != nil {
		t.Fatal(err)
	}

	identity := ristretto255.NewElement().Zero()

	if _, _, err := cpace.Exchange(password, c, identity.Encode(msgA[:16])); err == nil {
		t.Error("expected error for identity value")
	}
	if _, err := s.Finish(identity.Encode(nil)); err == nil {
		t.Error("expected error for identity value")
	}
}
