#!/usr/bin/env roundup

source "$(dirname $1)/common.sh"

describe "mkcert -uninstall"

after() {
  cleanup
}

it_outputs_uninstall_text() {
  mkcert -install
  local want="$(mkcert -uninstall)"

  install
  test "$(run -uninstall)" = "$want"
}

it_retains_the_rootCA_pem_file() {
  install
  test -f "$CAROOT/rootCA.pem"

  run -uninstall
  test -f "$CAROOT/rootCA.pem"
}

it_retains_the_rootCA_key_pem_file() {
  install
  test -f "$CAROOT/rootCA-key.pem"

  run -uninstall
  test -f "$CAROOT/rootCA-key.pem"
}

it_prints_CAROOT_flag_error() {
  test_contains "ERROR: you can't set -\[un\]install and -CAROOT at the same time" \
    "$(run -uninstall -CAROOT "$CAROOT")"
}

it_ignores_certutil_validate_error() {
  setup_nss
  install
  stub_cmd certutil -V -d

  run -uninstall
  test -n "$(strings "$NSSDB/cert9.db" | grep mkcert)"
}

it_prints_certutil_delete_error() {
  setup_nss
  install
  stub_cmd certutil -D -d

  test_contains "ERROR: failed to execute \"certutil -D -d sql:$NSSDB\": exit status 42" \
    "$(run -uninstall)"
}

it_prints_keytool_error() {
  install
  stub_cmd keytool -delete -alias

  test_contains "ERROR: failed to execute \"keytool -delete\": exit status 42" \
    "$(JAVA_HOME="$(stub_java_home)" TRUST_STORES="java" run -uninstall)"
}

it_prints_keytool_not_available_warning() {
  local warning="$(cat <<WARNING

Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️

WARNING
)"
  install

  test "$(JAVA_HOME="/dev/null" TRUST_STORES="java" run -uninstall)" = "$warning"
}

if [ "$(uname -s)" = "Linux" ]; then
  it_prints_sudo_not_available_warning() {
    local nobody_dir="$(setuid nobody mktemp -d -t mkcert.nobody_dir.XXXXX)"

    go build -o "$nobody_dir/mkcert" ./

    test_contains "Warning: \"sudo\" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️" \
      "$(PATH="$STUBS_PATH" CAROOT="$nobody_dir" $(which setuid) nobody "$nobody_dir/mkcert" -uninstall 2>&1)"
  }

  it_prints_certutil_missing_warning() {
    local warning="$(cat <<WARNING
  Warning: "certutil" is not available, so the CA can\'t be automatically uninstalled from $NSS_BROWSERS (if it was ever installed)! ⚠️
  You can install "certutil" with "$INSTALL_CERTUTIL" and re-run "mkcert -uninstall" 👈
WARNING
)"

    setup_nss
    if [ "$(uname -s)" = "Linux" ]; then
      stub_cmd apt
    else
      stub_cmd brew --prefix nss
    fi

    test_contains "$warning" "$(PATH="$STUBS_PATH" TRUST_STORES="nss" run -uninstall)"
  }
fi
