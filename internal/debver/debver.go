// Package debver parses and compares Debian package versions
// as described in Debian Policy §5.6.12.
package debver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed Debian version: [epoch:]upstream[-revision].
type Version struct {
	Epoch    int
	Upstream string
	Revision string
}

// Parse splits a version string into its parts. It is deliberately lenient
// about upstream syntax (real archives contain oddities) but rejects
// empty versions and malformed epochs.
func Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, fmt.Errorf("empty version")
	}
	var v Version
	if i := strings.IndexByte(s, ':'); i >= 0 {
		e, err := strconv.Atoi(s[:i])
		if err != nil || e < 0 {
			return Version{}, fmt.Errorf("bad epoch in %q", s)
		}
		v.Epoch = e
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.Revision = s[i+1:]
		s = s[:i]
	}
	if s == "" {
		return Version{}, fmt.Errorf("empty upstream version")
	}
	v.Upstream = s
	return v, nil
}

func (v Version) String() string {
	s := v.Upstream
	if v.Epoch != 0 {
		s = strconv.Itoa(v.Epoch) + ":" + s
	}
	if v.Revision != "" {
		s += "-" + v.Revision
	}
	return s
}

// Compare returns -1, 0 or 1 as a is less than, equal to or greater than b.
func (a Version) Compare(b Version) int {
	if a.Epoch != b.Epoch {
		return sign(a.Epoch - b.Epoch)
	}
	if c := verrevcmp(a.Upstream, b.Upstream); c != 0 {
		return sign(c)
	}
	return sign(verrevcmp(a.Revision, b.Revision))
}

// Compare parses and compares two version strings. Unparseable versions
// sort before parseable ones and are otherwise compared as plain strings,
// so sorting never fails.
func Compare(a, b string) int {
	va, ea := Parse(a)
	vb, eb := Parse(b)
	switch {
	case ea != nil && eb != nil:
		return strings.Compare(a, b)
	case ea != nil:
		return -1
	case eb != nil:
		return 1
	}
	return va.Compare(vb)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order gives the sort weight of a non-digit character: '~' sorts before
// everything (even the end of the string), letters before non-letters.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

// verrevcmp is a port of dpkg's lib/dpkg/version.c:verrevcmp.
func verrevcmp(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}
