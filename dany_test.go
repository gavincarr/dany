package dany

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewResolvers(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	r := NewResolvers(ip)
	if r.Length != 1 {
		t.Errorf("Length = %d, want 1", r.Length)
	}
	if !r.List[0].Equal(ip) {
		t.Errorf("List[0] = %v, want %v", r.List[0], ip)
	}
}

func TestResolversAppend(t *testing.T) {
	r := NewResolvers(net.ParseIP("8.8.8.8"))
	r.Append(net.ParseIP("1.1.1.1"))
	r.Append(net.ParseIP("9.9.9.9"))
	if r.Length != 3 {
		t.Fatalf("Length = %d, want 3", r.Length)
	}
	want := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}
	for i, w := range want {
		if r.List[i].String() != w {
			t.Errorf("List[%d] = %s, want %s", i, r.List[i], w)
		}
	}
}

func TestResolversNextRotation(t *testing.T) {
	r := NewResolvers(net.ParseIP("8.8.8.8"))
	r.Append(net.ParseIP("1.1.1.1"))
	r.Append(net.ParseIP("9.9.9.9"))

	// Calling Next() five times across three resolvers should cycle.
	want := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.1.1.1"}
	for i, w := range want {
		if got := r.Next().String(); got != w {
			t.Errorf("Next() call %d = %s, want %s", i, got, w)
		}
	}
}

func TestResolversNextSingleStable(t *testing.T) {
	r := NewResolvers(net.ParseIP("8.8.8.8"))
	for i := 0; i < 5; i++ {
		if got := r.Next().String(); got != "8.8.8.8" {
			t.Errorf("Next() call %d = %s, want 8.8.8.8", i, got)
		}
	}
}

func TestLoadResolvers(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string  // empty means: expect error
		errSub  string    // substring expected in error message
	}{
		{
			name:    "single IPv4",
			content: "8.8.8.8\n",
			want:    []string{"8.8.8.8"},
		},
		{
			name:    "multiple IPv4",
			content: "8.8.8.8\n1.1.1.1\n9.9.9.9\n",
			want:    []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"},
		},
		{
			name:    "IPv6",
			content: "2001:4860:4860::8888\n",
			want:    []string{"2001:4860:4860::8888"},
		},
		{
			name:    "no trailing newline",
			content: "8.8.8.8",
			want:    []string{"8.8.8.8"},
		},
		{
			name:    "empty file",
			content: "",
			errSub:  "no resolvers found",
		},
		{
			name:    "invalid IP",
			content: "not-an-ip\n",
			errSub:  "failed to parse",
		},
		{
			name:    "blank line mid-file",
			content: "8.8.8.8\n\n1.1.1.1\n",
			errSub:  "failed to parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolvers.txt")
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			r, err := LoadResolvers(path)
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Errorf("error = %q, want substring %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if r.Length != len(tc.want) {
				t.Fatalf("Length = %d, want %d", r.Length, len(tc.want))
			}
			for i, w := range tc.want {
				if r.List[i].String() != w {
					t.Errorf("List[%d] = %s, want %s", i, r.List[i], w)
				}
			}
		})
	}
}

func TestLoadResolversMissingFile(t *testing.T) {
	_, err := LoadResolvers(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
