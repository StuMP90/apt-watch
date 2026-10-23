package collect

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aptwatch/internal/runx"
)

// writeTree writes files (path relative to root → body) under root.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, body)
	}
}

const (
	nginxMaps = `55d0c0a00000-55d0c0a20000 r--p 00000000 08:01 1234 /usr/sbin/nginx
7f1c2a000000-7f1c2a1a0000 r-xp 00000000 08:01 2345 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1c2a1a0000-7f1c2a1c0000 r--p 001a0000 08:01 2345 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1c2b000000-7f1c2b100000 r--p 00000000 08:01 3456 /usr/lib/locale/locale-archive (deleted)
7f1c2c000000-7f1c2c010000 rw-s 00000000 00:01 4567 /memfd:pulseaudio (deleted)
7f1c2d000000-7f1c2d200000 r-xp 00000000 08:01 5678 /usr/lib/x86_64-linux-gnu/libc.so.6
`
	sshdMaps = `7f1c2a000000-7f1c2a1a0000 r-xp 00000000 08:01 2345 /lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)
`
)

func TestRestarts(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		// nginx: master and worker, cgroup v2.
		"/proc/100/maps":   nginxMaps,
		"/proc/100/cgroup": "0::/system.slice/nginx.service\n",
		"/proc/101/maps":   nginxMaps,
		"/proc/101/cgroup": "0::/system.slice/nginx.service\n",
		// sshd, cgroup v1, a merged-/usr path.
		"/proc/200/maps":   sshdMaps,
		"/proc/200/cgroup": "12:pids:/system.slice/ssh.service\n1:name=systemd:/system.slice/ssh.service\n",
		// A user session and a container: left out.
		"/proc/300/maps":   nginxMaps,
		"/proc/300/cgroup": "0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service\n",
		"/proc/400/maps":   nginxMaps,
		"/proc/400/cgroup": "0::/system.slice/docker-0123abcd.scope\n",
		// A kernel thread and a process with nothing deleted.
		"/proc/2/maps":               "",
		"/proc/2/cgroup":             "0::/\n",
		"/proc/500/maps":             "7f1c2d000000-7f1c2d200000 r-xp 00000000 08:01 5678 /usr/lib/x86_64-linux-gnu/libc.so.6\n",
		"/proc/500/cgroup":           "0::/system.slice/cron.service\n",
		"/proc/sys/kernel/osrelease": "6.1.0-41-amd64\n",

		"/var/lib/dpkg/info/libssl3:amd64.list": "/.\n/usr\n/usr/lib/x86_64-linux-gnu/libssl.so.3\n/usr/lib/x86_64-linux-gnu/libcrypto.so.3\n",
		"/var/lib/dpkg/info/libc6:amd64.list":   "/.\n/usr/lib/x86_64-linux-gnu/libc.so.6\n",
		"/var/log/dpkg.log.1":                   "2026-10-01 06:00:00 upgrade libssl3:amd64 3.0.16-1~deb12u1 3.0.17-1~deb12u2\n",
		"/var/log/dpkg.log": "2026-10-20 06:12:01 startup archives unpack\n" +
			"2026-10-20 06:12:01 upgrade libssl3:amd64 3.0.17-1~deb12u2 3.0.17-1~deb12u3\n" +
			"2026-10-20 06:12:02 status installed libssl3:amd64 3.0.17-1~deb12u3\n",
	})

	rs, unreadable, err := Host{Root: root}.Restarts()
	if err != nil || unreadable != 0 {
		t.Fatalf("err %v, unreadable %d", err, unreadable)
	}
	libssl := []RestartPkg{{Name: "libssl3", Previous: "3.0.16-1~deb12u1"}}
	want := []Restart{
		{Unit: "nginx.service", Files: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}, Packages: libssl},
		{Unit: "ssh.service", Files: []string{"/lib/x86_64-linux-gnu/libcrypto.so.3"}, Packages: libssl},
	}
	if !reflect.DeepEqual(rs, want) {
		t.Errorf("got  %+v\nwant %+v", rs, want)
	}
}

func TestRestartsNone(t *testing.T) {
	rs, unreadable, err := Host{Root: t.TempDir()}.Restarts()
	if rs != nil || unreadable != 0 || err != nil {
		t.Errorf("empty /proc: %+v, %d, %v", rs, unreadable, err)
	}
}

func TestRestartsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"/proc/100/maps": nginxMaps, "/proc/100/cgroup": "0::/system.slice/nginx.service\n"})
	if err := os.Chmod(filepath.Join(root, "/proc/100/maps"), 0); err != nil {
		t.Fatal(err)
	}
	rs, unreadable, err := Host{Root: root}.Restarts()
	if rs != nil || unreadable != 1 || err != nil {
		t.Errorf("got %+v, %d, %v; want 1 unreadable", rs, unreadable, err)
	}
}

func TestServiceUnit(t *testing.T) {
	dir := t.TempDir()
	for cg, want := range map[string]string{
		"0::/system.slice/system-getty.slice/getty@tty1.service\n": "getty@tty1.service",
		"0::/system.slice/docker.service/sub\n":                    "docker.service",
		"0::/init.scope\n":                                         "",
		"0::/user.slice/user-1000.slice/session-3.scope\n":         "",
		"": "",
	} {
		p := filepath.Join(dir, "cgroup")
		writeFile(t, p, cg)
		if got := serviceUnit(p); got != want {
			t.Errorf("%q: got %q, want %q", cg, got, want)
		}
	}
}

const policyOut = `openssl:amd64:
  Installed: 3.0.17-1~deb12u2
  Candidate: 3.0.17-1~deb12u3
  Version table:
     3.0.17-1~deb12u3 500
        500 http://security.debian.org/debian-security bookworm-security/main amd64 Packages
 *** 3.0.17-1~deb12u2 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
        100 /var/lib/dpkg/status
nginx:
  Installed: 1.22.1-9
  Candidate: 1.22.1-9+deb12u1
  Version table:
     1.22.1-9+deb12u1 500
        500 http://deb.debian.org/debian bookworm-updates/main amd64 Packages
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
 *** 1.22.1-9 100
        100 /var/lib/dpkg/status
zsh:
  Installed: 5.9-4+b6
  Candidate: 5.9-4+b6
  Version table:
 *** 5.9-4+b6 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
        100 /var/lib/dpkg/status
`

func TestHeldPackages(t *testing.T) {
	pkgs := []Package{
		{Name: "openssl", Arch: "amd64", Version: "3.0.17-1~deb12u2", Hold: true},
		{Name: "nginx", Arch: "amd64", Version: "1.22.1-9", Hold: true},
		{Name: "zsh", Arch: "amd64", Version: "5.9-4+b6", Hold: true},
		{Name: "curl", Arch: "amd64", Version: "7.88.1-10+deb12u14"},
	}
	var args []string
	run := func(_ context.Context, c runx.Cmd) (runx.Result, error) {
		args = append([]string{c.Name}, c.Args...)
		return runx.Result{Stdout: []byte(policyOut)}, nil
	}
	held, err := Host{Run: run}.HeldPackages(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(args, " "); got != "apt-cache policy openssl:amd64 nginx:amd64 zsh:amd64" {
		t.Errorf("ran %q", got)
	}
	want := []Held{
		{Package: "openssl", Arch: "amd64", Installed: "3.0.17-1~deb12u2", Candidate: "3.0.17-1~deb12u3", Suites: []string{"bookworm-security"}, Security: true},
		{Package: "nginx", Arch: "amd64", Installed: "1.22.1-9", Candidate: "1.22.1-9+deb12u1", Suites: []string{"bookworm-updates", "bookworm"}},
		{Package: "zsh", Arch: "amd64", Installed: "5.9-4+b6"},
	}
	if !reflect.DeepEqual(held, want) {
		t.Errorf("got  %+v\nwant %+v", held, want)
	}

	held, err = Host{Run: run}.HeldPackages(context.Background(), pkgs[3:])
	if held != nil || err != nil {
		t.Errorf("no holds: %+v, %v", held, err)
	}
}

func TestParseLivepatch(t *testing.T) {
	out := `{"client-version":"10.11.2","architecture":"x86_64","status":[
{"kernel":"6.8.0-85.85-generic","running":false,"livepatch":{"checkState":"checked","state":"nothing-to-apply"}},
{"kernel":"6.8.0-79.79-generic","running":true,"livepatch":{"checkState":"checked","state":"applied","version":"118.1"}}]}`
	lp, err := ParseLivepatch([]byte(out))
	want := &Livepatch{Kernel: "6.8.0-79.79-generic", State: "applied", Version: "118.1"}
	if err != nil || !reflect.DeepEqual(lp, want) || !lp.Applied() {
		t.Errorf("got %+v, %v", lp, err)
	}
	if _, err := ParseLivepatch([]byte("Machine is not enabled")); err == nil {
		t.Error("bad output: no error")
	}

	fail := func(context.Context, runx.Cmd) (runx.Result, error) {
		return runx.Result{}, os.ErrNotExist
	}
	if lp, err := (Host{Run: fail}).Livepatch(context.Background()); lp != nil || err != nil {
		t.Errorf("client missing: %+v, %v", lp, err)
	}
}
