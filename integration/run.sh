#!/bin/sh
# Runs inside a throwaway container as root. Installs an old version of one
# package that has a newer version in the security pocket, then runs
# aptwatch. Writes to /out: picked (package, old and security versions),
# report.json, stderr and exit.
set -eu
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

apt-get update -qq
# What the .deb depends on and recommends.
apt-get install -y -qq --no-install-recommends ca-certificates xz-utils distro-info-data >/dev/null

. /etc/os-release
codename=$VERSION_CODENAME

# Prints "package version installed-size" for each stanza in the apt
# indexes whose file names contain $1.
idx() {
	for f in /var/lib/apt/lists/*"$1"*Packages*; do
		[ -e "$f" ] || continue
		/usr/lib/apt/apt-helper cat-file "$f"
	done | awk '/^Package:/ {p = $2} /^Version:/ {v = $2} /^Installed-Size:/ {s = $2}
		/^$/ {if (p != "") print p, v, s + 0; p = ""} END {if (p != "") print p, v, s + 0}'
}

# Fallback after a point release has folded the preferred packages' fixes
# into the release pocket: any package with a newer version in the security
# pocket, smallest first.
fallback() {
	idx "_dists_${codename}_" | sort -k1,1 -u >/tmp/rel
	idx "_dists_${codename}-security_" | sort -k1,1 -u >/tmp/sec
	join /tmp/rel /tmp/sec | while read -r p rv _ sv size; do
		dpkg --compare-versions "$rv" lt "$sv" && echo "$size $p"
	done | sort -n | awk '$2 !~ /^linux-|-dbg$|-doc$/ {print $2}' | head -n 30
}

# Preferred packages have no exact-version dependencies on other binaries
# from the same source, so the old version installs on its own.
for p in sudo wget rsync less unzip tar gzip openssh-client libexpat1 bzip2 cpio patch $(fallback); do
	sec=$(apt-cache madison "$p" | awk -F' [|] ' -v s="$codename-security/" 'index($3, s) {print $2; exit}')
	rel=$(apt-cache madison "$p" | awk -F' [|] ' -v s=" $codename/" 'index($3, s) {print $2; exit}')
	[ -n "$sec" ] && [ -n "$rel" ] || continue
	dpkg --compare-versions "$rel" lt "$sec" || continue
	if apt-get install -y -qq --allow-downgrades --no-install-recommends "$p=$rel" >/dev/null 2>&1; then
		echo "$p $rel $sec" >/out/picked
		break
	fi
done
[ -s /out/picked ] || { echo "no package with an older release version found" >&2; exit 1; }

mkdir -p /etc/aptwatch
: >/etc/aptwatch/config.yaml
chmod 600 /etc/aptwatch/config.yaml

set +e
aptwatch run --format json >/out/report.json 2>/out/stderr
echo $? >/out/exit
