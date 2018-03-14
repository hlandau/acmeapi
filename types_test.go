package acmeapi

import (
	"encoding/json"
	"testing"
)

func TestStatus(t *testing.T) {
	var s OrderStatus
	err := json.Unmarshal([]byte(`"pending"`), &s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if s != "pending" || !s.IsWellFormed() || s.IsFinal() {
		t.Fatal()
	}
	err = json.Unmarshal([]byte(`"f9S0"`), &s)
	if err == nil {
		t.Fatal()
	}
}
