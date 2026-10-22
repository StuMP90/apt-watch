package debver

import "testing"

// Vectors taken from dpkg's t-version.c and apt's versiontest data.
var vectors = []struct {
	a, b string
	want int
}{
	{"1.0", "1.0", 0},
	{"1.0", "1.1", -1},
	{"1.1", "1.0", 1},
	{"0:1.0", "1.0", 0},
	{"1:1.0", "2.0", 1},
	{"1.0-1", "1.0-2", -1},
	{"1.0-1", "1.0", 1},
	{"1.0", "1.0-0", 0},
	{"1.0~rc1", "1.0", -1},
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~~", "1.0~", -1},
	{"1.0~~a", "1.0~~", 1},
	{"1.0~", "1.0", -1},
	{"1.0a", "1.0", 1},
	{"1.0+b1", "1.0", 1},
	{"1.0.1", "1.0a", 1}, // non-letters sort after letters
	{"1.2.3", "1.2.3", 0},
	{"1.10", "1.9", 1},
	{"1.001", "1.1", 0},
	{"2.80.0-6ubuntu3.10", "2.80.0-6ubuntu3.9", 1},
	{"3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.4", 1},
	{"6.11.0-21.21~24.04.1+1", "6.11.0-21.21~24.04.1", 1},
	{"1.2.3~bpo12+1", "1.2.3", -1},
	{"1.2.3-1~deb12u1", "1.2.3-1", -1},
	{"1.2.3-1+deb12u1", "1.2.3-1", 1},
	{"7.6.q-19", "7.6-1", 1},
	{"0.4a6-2", "0.4-1", 1},
	{"1:0.4", "10.3", 1},
	{"1.18.36:5.4", "1.18.36:5.5", -1},
	{"2:4.2.1-1", "2:4.2.1-1ubuntu1", -1},
	{"a", "b", -1},
	{"~", "", -1},
	{"", "~", 1},
}

func TestVerrevcmpVectors(t *testing.T) {
	for _, v := range vectors {
		if v.a == "" || v.b == "" {
			// Raw string comparison for edge cases that aren't valid versions.
			if got := sign(verrevcmp(v.a, v.b)); got != v.want {
				t.Errorf("verrevcmp(%q,%q) = %d, want %d", v.a, v.b, got, v.want)
			}
			continue
		}
		if got := Compare(v.a, v.b); got != v.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", v.a, v.b, got, v.want)
		}
		if got := Compare(v.b, v.a); got != -v.want {
			t.Errorf("Compare(%q,%q) = %d, want %d (reversed)", v.b, v.a, got, -v.want)
		}
	}
}

func TestParse(t *testing.T) {
	v, err := Parse("1:2.80.0-6ubuntu3.10")
	if err != nil {
		t.Fatal(err)
	}
	if v.Epoch != 1 || v.Upstream != "2.80.0" || v.Revision != "6ubuntu3.10" {
		t.Errorf("got %+v", v)
	}
	if v.String() != "1:2.80.0-6ubuntu3.10" {
		t.Errorf("String() = %q", v.String())
	}
	for _, bad := range []string{"", "x:1.0", "-1:1.0", "1:", "-1"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", bad)
		}
	}
}
