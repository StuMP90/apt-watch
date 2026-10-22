package collect

import (
	"bufio"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"aptwatch/internal/debver"
)

// OSRelease holds the fields of /etc/os-release that aptwatch uses.
type OSRelease struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	Codename   string `json:"codename"`
	PrettyName string `json:"pretty_name"`
}

// EOL gives a release's support dates. SecurityEnd is the end of free
// security support (Debian LTS included). ExtendedEnd is Ubuntu ESM
// (needs Pro) or Debian ELTS (commercial).
type EOL struct {
	SecurityEnd time.Time `json:"security_end"`
	ExtendedEnd time.Time `json:"extended_end,omitzero"`
	Note        string    `json:"note,omitempty"`
}

// Reboot describes /run/reboot-required.
type Reboot struct {
	Required bool      `json:"required"`
	Since    time.Time `json:"since,omitzero"`
	Packages []string  `json:"packages,omitempty"`
}

// Kernel compares the running kernel with the newest installed one.
type Kernel struct {
	Running string `json:"running"`
	Newest  string `json:"newest,omitempty"` // release string, e.g. 6.8.0-91-generic
}

// System is the collected host state.
type System struct {
	Hostname     string    `json:"hostname"`
	OS           OSRelease `json:"os"`
	EOL          *EOL      `json:"eol,omitempty"`
	Reboot       Reboot    `json:"reboot"`
	Kernel       Kernel    `json:"kernel"`
	ListsUpdated time.Time `json:"apt_lists_updated"`
}

func ReadOSRelease(path string) (OSRelease, error) {
	f, err := os.Open(path)
	if err != nil {
		return OSRelease{}, err
	}
	defer f.Close()
	return ParseOSRelease(f)
}

func ParseOSRelease(r io.Reader) (OSRelease, error) {
	var o OSRelease
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_ID":
			o.VersionID = v
		case "VERSION_CODENAME":
			o.Codename = v
		case "UBUNTU_CODENAME":
			if o.Codename == "" {
				o.Codename = v
			}
		case "PRETTY_NAME":
			o.PrettyName = v
		}
	}
	return o, sc.Err()
}

// LookupEOL reads the distro-info-data CSV for osID and finds codename.
func LookupEOL(dir, osID, codename string) (*EOL, error) {
	f, err := os.Open(dir + "/" + osID + ".csv")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseDistroInfo(f, osID, codename)
}

// ParseDistroInfo finds codename in a distro-info-data CSV.
func ParseDistroInfo(r io.Reader, osID, codename string) (*EOL, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // unreleased versions have short rows
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, errors.New("distro-info: empty file")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	get := func(row []string, name string) time.Time {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return time.Time{}
		}
		t, _ := time.Parse("2006-01-02", row[i])
		return t
	}
	for _, row := range rows[1:] {
		if i, ok := col["series"]; !ok || i >= len(row) || row[i] != codename {
			continue
		}
		e := &EOL{}
		switch osID {
		case "ubuntu":
			e.SecurityEnd = get(row, "eol-server")
			if e.SecurityEnd.IsZero() {
				e.SecurityEnd = get(row, "eol")
			}
			e.ExtendedEnd = get(row, "eol-esm")
			if !e.ExtendedEnd.IsZero() {
				e.Note = "ESM (Ubuntu Pro) until " + e.ExtendedEnd.Format("2006-01-02")
			}
		case "debian":
			e.SecurityEnd = get(row, "eol-lts")
			if e.SecurityEnd.IsZero() {
				e.SecurityEnd = get(row, "eol")
			} else if eol := get(row, "eol"); !eol.IsZero() {
				e.Note = "regular security support ends " + eol.Format("2006-01-02") + ", then Debian LTS"
			}
			e.ExtendedEnd = get(row, "eol-elts")
		}
		if e.SecurityEnd.IsZero() {
			return nil, nil // release with no announced EOL yet
		}
		return e, nil
	}
	return nil, errors.New("distro-info: " + codename + " not found")
}

// ReadReboot checks /run/reboot-required and its .pkgs companion.
func ReadReboot(path string) (Reboot, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Reboot{}, nil
	}
	if err != nil {
		return Reboot{}, err
	}
	r := Reboot{Required: true, Since: info.ModTime()}
	if b, err := os.ReadFile(path + ".pkgs"); err == nil {
		seen := map[string]bool{}
		for _, p := range strings.Fields(string(b)) {
			if !seen[p] {
				seen[p] = true
				r.Packages = append(r.Packages, p)
			}
		}
	}
	return r, nil
}

// NewestKernel returns the release string (e.g. "6.8.0-91-generic") of the
// highest-versioned installed linux-image package with the same flavour
// as running. Ubuntu's unsigned images are named linux-image-unsigned-REL
// and Debian's linux-image-REL-unsigned.
func NewestKernel(pkgs []Package, running string) string {
	flavour := kernelFlavour(running)
	var best, bestVer string
	for _, p := range pkgs {
		rel, ok := strings.CutPrefix(p.Name, "linux-image-")
		if !ok {
			continue
		}
		rel = strings.TrimSuffix(strings.TrimPrefix(rel, "unsigned-"), "-unsigned")
		if rel == "" || rel[0] < '0' || rel[0] > '9' || kernelFlavour(rel) != flavour {
			continue
		}
		if best == "" || debver.Compare(p.Version, bestVer) > 0 {
			best, bestVer = rel, p.Version
		}
	}
	return best
}

// kernelFlavour returns the part of a kernel release after its version
// and ABI: "generic" for 6.8.0-91-generic, "generic-64k" for
// 6.8.0-91-generic-64k, "cloud-amd64" for 6.1.0-41-cloud-amd64 and "amd64"
// for 6.12.48+deb13-amd64.
func kernelFlavour(rel string) string {
	parts := strings.Split(rel, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" && (parts[i][0] < '0' || parts[i][0] > '9') {
			return strings.Join(parts[i:], "-")
		}
	}
	return ""
}

// RunningKernel returns the kernel release, as uname -r prints it.
func RunningKernel() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b)), err
}
