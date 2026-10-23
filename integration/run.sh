#!/bin/sh
# Runs inside a throwaway container as root. Installs an old version of one
# package that has a newer version in the security pocket, then runs
# aptwatch. Writes to /out: picked (package, old and security versions),
# report.json, stderr and exit.
set -eu
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
# What the .deb depends on and recommends.
apt-get install -y -qq --no-install-recommends ca-certificates xz-utils distro-info-data >/dev/null

. /etc/os-release
codename=$VERSION_CODENAME

# Packages without exact-version dependencies on other binaries from the
# same source, so the old version installs on its own.
for p in sudo wget rsync less unzip tar gzip openssh-client libexpat1 bzip2 cpio patch; do
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
