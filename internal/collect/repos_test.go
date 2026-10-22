package collect

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeLists(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		data := []byte(body)
		if filepath.Ext(name) == ".gz" {
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			zw.Write(data)
			zw.Close()
			data = b.Bytes()
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const inRelease = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: %s\nLabel: x\nSuite: noble\nSHA256:\n abc 1 main/binary-amd64/Packages\n"

func release(origin string) string { return fmt.Sprintf(inRelease, origin) }

func TestAddRepos(t *testing.T) {
	dir := writeLists(t, map[string]string{
		"archive.ubuntu.com_ubuntu_dists_noble_InRelease":                           release("Ubuntu"),
		"archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages":          "Package: php8.3-cli\nVersion: 8.3.6-0ubuntu0.24.04.1\n\nPackage: bash\nVersion: 5.2-1\n\nPackage: postgresql-16\nVersion: 16.2-1\n",
		"archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease":                   release("Ubuntu"),
		"archive.ubuntu.com_ubuntu_dists_noble-updates_main_binary-amd64_Packages":  "Package: bash\nVersion: 5.2-1ubuntu1\n",
		"ppa.example.org_php_ubuntu_dists_noble_InRelease":                          release("LP-PPA-example-php"),
		"ppa.example.org_php_ubuntu_dists_noble_main_binary-amd64_Packages.gz":      "Package: php8.3-cli\nVersion: 8.3.20-1+ppa1\n\nPackage: php8.3-fpm\nVersion: 8.3.20-1+ppa1\n",
		"apt.example.net_pg_dists_noble-pgdg_InRelease":                             release("apt.example.net"),
		"apt.example.net_pg_dists_noble-pgdg_main_binary-amd64_Packages":            "Package: postgresql-16\nVersion: 16.4-1.pgdg24.04+1\n\nPackage: pgtool\nVersion: 2.0-1\n",
		"apt.example.net_pg_dists_noble-pgdg_main_binary-i386_Packages":             "Package: pgtool\nVersion: 2.0-1\n",
		"apt.example.net_pg_dists_noble-pgdg_main_binary-amd64_Packages.xz.partial": "junk",
	})
	pkgs := []Package{
		{Name: "bash", Version: "5.2-1ubuntu1"},
		{Name: "php8.3-cli", Version: "8.3.19-1+ppa1"}, // superseded PPA build
		{Name: "php8.3-fpm", Version: "8.3.20-1+ppa1"},
		{Name: "postgresql-16", Version: "16.2-1"},       // the distro's build
		{Name: "pgtool", Version: "1.0-1"},               // superseded, not in the distro
		{Name: "mytool", Version: "1.0"},                 // dpkg -i
		{Name: "php8.3-common", Version: "8.3.6-0local"}, // no index has it
	}
	if err := AddRepos(dir, pkgs); err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Repo: "archive.ubuntu.com/ubuntu", InDistro: true},
		{Repo: "ppa.example.org/php/ubuntu", ThirdParty: true, InDistro: true},
		{Repo: "ppa.example.org/php/ubuntu", ThirdParty: true},
		{Repo: "archive.ubuntu.com/ubuntu", InDistro: true},
		{Repo: "apt.example.net/pg", ThirdParty: true},
		{Local: true},
		{Local: true},
	}
	for i, w := range want {
		p := pkgs[i]
		if p.Repo != w.Repo || p.ThirdParty != w.ThirdParty || p.InDistro != w.InDistro || p.Local != w.Local {
			t.Errorf("%s: got repo=%q third=%v distro=%v local=%v, want %+v", p.Name, p.Repo, p.ThirdParty, p.InDistro, p.Local, w)
		}
	}
}

func TestAddReposNoLists(t *testing.T) {
	pkgs := []Package{{Name: "bash", Version: "1"}}
	if err := AddRepos(t.TempDir(), pkgs); err == nil {
		t.Error("no error for an empty lists dir")
	}
	if pkgs[0].Local || pkgs[0].ThirdParty {
		t.Errorf("classified without lists: %+v", pkgs[0])
	}
}

func TestRepoName(t *testing.T) {
	for in, want := range map[string]string{
		"ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_":    "ppa.launchpadcontent.net/ondrej/php/ubuntu",
		"deb.nodesource.com_node%5f22.x_dists_nodistro_":             "deb.nodesource.com/node_22.x",
		"download.opensuse.org_repositories_home:x_xUbuntu%5f24.10_": "download.opensuse.org/repositories/home:x/xUbuntu_24.10",
	} {
		if got := repoName(in); got != want {
			t.Errorf("repoName(%q) = %q, want %q", in, got, want)
		}
	}
}
