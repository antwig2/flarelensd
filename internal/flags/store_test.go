package flags

import (
	"testing"
)

func TestFlagStoreUpdateAndQuery(t *testing.T) {
	store := NewStore(nil)

	// Test initial state
	if store.IsEnabled("non_existent_flag") {
		t.Errorf("Expected non-existent flag to be false")
	}

	// Single flag update from JSON
	singleJSON := []byte(`{"key":"mpesa_express_v2","description":"MPESA STK push","enabled":true,"rollout_pct":100}`)
	if err := store.UpdateFromJSON(singleJSON); err != nil {
		t.Fatalf("Failed to update from single flag JSON: %v", err)
	}

	if !store.IsEnabled("mpesa_express_v2") {
		t.Errorf("Expected mpesa_express_v2 to be true")
	}

	// Batch flags update
	batchJSON := []byte(`[
		{"key":"flag_a","enabled":true},
		{"key":"flag_b","enabled":false}
	]`)
	if err := store.UpdateFromJSON(batchJSON); err != nil {
		t.Fatalf("Failed to update from batch flags JSON: %v", err)
	}

	if !store.IsEnabled("flag_a") {
		t.Errorf("Expected flag_a to be true")
	}
	if store.IsEnabled("flag_b") {
		t.Errorf("Expected flag_b to be false")
	}

	all := store.GetAll()
	if len(all) < 2 {
		t.Errorf("Expected at least 2 flags, got %d", len(all))
	}
}
