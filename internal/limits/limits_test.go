package limits

import "testing"

func TestNormalizeFillsZeroFields(t *testing.T) {
	got := Limits{}.Normalize()
	if got != Default() {
		t.Fatalf("zero value normalised to %+v, want %+v", got, Default())
	}
	custom := Limits{MaxList: 7, MaxMeta: 9, MaxDepth: 1}.Normalize()
	if custom != (Limits{MaxList: 7, MaxMeta: 9, MaxDepth: 1}) {
		t.Fatalf("explicit values must survive: %+v", custom)
	}
	if neg := (Limits{MaxList: -1, MaxMeta: -5, MaxDepth: -2}).Normalize(); neg != Default() {
		t.Fatalf("negative values must fall back to defaults: %+v", neg)
	}
}

func TestForSizeScalesWithInput(t *testing.T) {
	tests := []struct {
		name           string
		size           int64
		wantList       int
		wantMetaAtMost int64
	}{
		{"negative", -5, minList, 4096},
		{"empty", 0, minList, 4096},
		{"tiny", 1024, minList, 4096},
		{"medium", 400_000, 5000, 400_000},
		{"huge", 1 << 40, defaultMaxList, defaultMaxMeta},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ForSize(tc.size)
			if got.MaxList != tc.wantList {
				t.Errorf("MaxList = %d, want %d", got.MaxList, tc.wantList)
			}
			if got.MaxMeta > tc.wantMetaAtMost || got.MaxMeta <= 0 {
				t.Errorf("MaxMeta = %d, want 0 < x <= %d", got.MaxMeta, tc.wantMetaAtMost)
			}
			if got.MaxDepth != defaultMaxDepth {
				t.Errorf("MaxDepth = %d", got.MaxDepth)
			}
		})
	}
}
