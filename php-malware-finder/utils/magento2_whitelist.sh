#!/bin/bash
# Quit script if something goes wrong
set  -o errexit  -o nounset  -o pipefail;

SCRIPTDIR="$( dirname "$(readlink -f "$0")" )";
OUTFILE="${SCRIPTDIR}/../whitelists/magento2.yar";
TMPFILE="${OUTFILE}.new";

# First empty the target whitelist so we can completely generate a new one
cat <<EOF >"${OUTFILE}";
private rule Magento2 : ECommerce
{
	condition:
		false
}
EOF

# Create a temporary directory and make sure it is empty
GENTEMPDIR="$( mktemp -d --suffix="_gen_whitelist_m2" )";

# Composer access tokens
if [ ! -f "${HOME}/.composer/auth.json" ]; then
    echo -e "\nYou have no '.composer/auth.json' in your home dir. We will create it from a template and open an editor.";
    echo -e "Press [Enter] to continue. Press Ctrl-C if you wish to leave.";
    read;
    mkdir -p "${HOME}/.composer";
    cat <<EOF >"${HOME}/.composer/auth.json"    
{
  "INFO_GITHUB": "==== GET TOKEN: https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/ ====",
  "github-oauth": {
    "github.com": "---github-token-goes-here---"
  },
  "INFO_MAGENTO": "==== GET TOKEN: https://devdocs.magento.com/guides/v2.0/install-gde/prereq/connect-auth.html ====",
  "http-basic": {
    "repo.magento.com": {
      "username": "---public-key-goes-here---",
      "password": "---private-key-goes-here---"
    }
  }
}
EOF
    editor "${HOME}/.composer/auth.json";
fi

# Add header to whitelist tempfile
cat <<EOF | tee "${TMPFILE}";
private rule Magento2 : ECommerce
{
	condition:
EOF

# Fetch tags (releases) from Github repo
TAGS=$( git ls-remote --tags https://github.com/magento/magento2.git | cut -d '/' -f3 | grep -P '^[\d\.]+$' | sort -V );

# Foreach tag (release)
while read -r TAG; do
    # Download tarball of release
    wget "https://github.com/magento/magento2/archive/${TAG}.tar.gz" -O "${GENTEMPDIR}/${TAG}.tgz";
    # Unpack tarball
    tar -C "${GENTEMPDIR}" -xpzf "${GENTEMPDIR}/${TAG}.tgz";
    # Run 'composer install' inside unpacked release
    SOURCEDIR="${GENTEMPDIR}/magento2-${TAG}";
    composer --working-dir="${SOURCEDIR}" -- install;
    # Add version comment to whitelist
    echo "		/* Magento2 ${TAG} */" | tee -a "${TMPFILE}";
    # Generate whitelist for version, add output to whitelist tempfile
    ${SCRIPTDIR}/generate_whitelist.py "Magento2 ${TAG}" "${SOURCEDIR}" | grep 'hash.sha1' | sed "s|// ${SOURCEDIR}/|// |" | tee -a "${TMPFILE}";
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
