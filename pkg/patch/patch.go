package patch

import (
	"encoding/json"
)

// PatchOperation represents a JSON Patch operation (RFC 6902)
type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// CreatePatch generates a JSON patch to add the "verified-by: va" label to a Pod.
// It handles cases where the labels map is empty/nil, or already has entries.
func CreatePatch(existingLabels map[string]string) ([]byte, error) {
	var patches []PatchOperation

	if existingLabels == nil {
		patches = append(patches, PatchOperation{
			Op:   "add",
			Path: "/metadata/labels",
			Value: map[string]string{
				"verified-by": "va",
			},
		})
	} else {
		patches = append(patches, PatchOperation{
			Op:    "add",
			Path:  "/metadata/labels/verified-by",
			Value: "va",
		})
	}

	return json.Marshal(patches)
}
