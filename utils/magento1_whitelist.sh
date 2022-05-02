#!/bin/bash
# Quit script if something goes wrong
set  -o errexit  -o nounset  -o pipefail;

SCRIPTDIR="$( dirname "$(readlink -f "$0")" )";
OUTFILE="${SCRIPTDIR}/../whitelists/magento1ce.yar";
TMPFILE="${OUTFILE}.new";

# First empty the target whitelist so we can completely generate a new one
cat <<EOF >"${OUTFILE}";
private rule Magento1Ce : ECommerce
{
	condition:
		false
}
EOF

# Create a temporary directory and make sure it is empty
GENTEMPDIR="$( mktemp -d --suffix="_gen_whitelist_m1" )";

# Add header to whitelist tempfile
cat <<EOF | tee "${TMPFILE}";
private rule Magento1Ce : ECommerce
{
	condition:
EOF

# Fetch tags (releases) from Github repo
TAGS=$( git ls-remote --tags https://github.com/OpenMage/magento-mirror.git | cut -d '/' -f3 | grep -P '^[\d\.]+$' );

# Foreach tag (release)
while read -r TAG; do
    # Download tarball of release
    wget "https://github.com/OpenMage/magento-mirror/archive/${TAG}.tar.gz" -O "${GENTEMPDIR}/${TAG}.tgz";
    # Unpack tarball
    tar -C "${GENTEMPDIR}" -xpzf "${GENTEMPDIR}/${TAG}.tgz";
    # Add version comment to whitelist tempfile
    echo "		/* Magento CE ${TAG} */" | tee -a "${TMPFILE}";
    # Generate whitelist for version, add output to whitelist tempfile
    ${SCRIPTDIR}/generate_whitelist.py "Magento CE ${TAG}" "${GENTEMPDIR}/magento-mirror-${TAG}" | grep 'hash.sha1' | sed "s|// ${GENTEMPDIR}/magento-mirror-${TAG}/|// |" | tee -a "${TMPFILE}";
    # Add white line, with indent
    echo "		" | tee -a "${TMPFILE}";
done <<< "${TAGS}";

# Add footer to whitelist tempfile
cat <<EOF | tee -a "${TMPFILE}";
		false
}
EOF

# Copy temporary file to target whitelist while removing duplicate lines except empty ones
cat "${TMPFILE}" | awk 'match($0,/^\s*$/)||!seen[$0]++' > "${OUTFILE}";

# Clean up
rm "${TMPFILE}";
rm -rf "${GENTEMPDIR}";
