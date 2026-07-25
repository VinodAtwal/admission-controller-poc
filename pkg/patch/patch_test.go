package patch

import (
	"encoding/json"
	"testing"
)

func TestCreatePatch(t *testing.T) {
	t.Run("nil labels", func(t *testing.T) {
		patchBytes, err := CreatePatch(nil)
		if err != nil {
			t.Fatalf("failed to create patch: %v", err)
		}

		var ops []PatchOperation
		if err := json.Unmarshal(patchBytes, &ops); err != nil {
			t.Fatalf("failed to unmarshal patch: %v", err)
		}

		if len(ops) != 1 {
			t.Fatalf("expected 1 patch operation, got %d", len(ops))
		}

		op := ops[0]
		if op.Op != "add" || op.Path != "/metadata/labels" {
			t.Errorf("unexpected operation: %+v", op)
		}

		valMap, ok := op.Value.(map[string]interface{})
		if !ok {
			t.Fatalf("expected value to be a map, got %T", op.Value)
		}

		if valMap["verified-by"] != "va" {
			t.Errorf("expected label verified-by to be 'va', got %v", valMap["verified-by"])
		}
	})

	t.Run("existing labels", func(t *testing.T) {
		existing := map[string]string{
			"app": "my-app",
		}
		patchBytes, err := CreatePatch(existing)
		if err != nil {
			t.Fatalf("failed to create patch: %v", err)
		}

		var ops []PatchOperation
		if err := json.Unmarshal(patchBytes, &ops); err != nil {
			t.Fatalf("failed to unmarshal patch: %v", err)
		}

		if len(ops) != 1 {
			t.Fatalf("expected 1 patch operation, got %d", len(ops))
		}

		op := ops[0]
		if op.Op != "add" || op.Path != "/metadata/labels/verified-by" {
			t.Errorf("unexpected operation: %+v", op)
		}

		if op.Value != "va" {
			t.Errorf("expected value to be 'va', got %v", op.Value)
		}
	})
}
