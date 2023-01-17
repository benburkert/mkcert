#!/usr/bin/env roundup

source "$(dirname $1)/common.sh"

describe "mkcert -install"

after() {
  cleanup
}

it_outputs_install_text() {
  local want="$(mkcert -install)"
  cleanup

  test "$(run -install)" = "$want"
}

it_prints_new_local_CA_text() {
  test_contains "Created a new local CA 💥" "$(run -install)"
}

it_generates_the_rootCA_pem_file() {
  ! test -f "$CAROOT/rootCA.pem"

  run -install
  test -f "$CAROOT/rootCA.pem"
}

it_generates_the_rootCA_key_pem_file() {
  ! test -f "$CAROOT/rootCA-key.pem"

  run -install
  test -f "$CAROOT/rootCA-key.pem"
}

it_prints_system_install_text() {
  test_contains "The local CA is now installed in the system trust store!" \
    "$(run -install)"
}

it_prints_firefox_install_text() {
  if [ "$(uname -s)" = "Linux" ]; then
    local firefox_text="The local CA is now installed in the Firefox and/or Chrome/Chromium trust store (requires browser restart)! 🦊"
  else
    local firefox_text="The local CA is now installed in the Firefox trust store (requires browser restart)! 🦊"
  fi

  setup_nss

  test_contains "$firefox_text" "$(run -install)"
}

it_adds_rootCA_to_nssdb() {
  setup_nss
  test -z "$(strings "$NSSDB/cert9.db" | grep mkcert)"

  run -install
  test -n "$(strings "$NSSDB/cert9.db" | grep mkcert)"
}

it_prints_no_security_database_error() {
  if [ "$(uname -s)" = "Linux" ]; then
    local firefox_text="ERROR: no Firefox and/or Chrome/Chromium security databases found"
  else
    local firefox_text="ERROR: no Firefox security databases found"
  fi

  mkdir -p "$NSSDB"
  ! test -f "$NSSDB/cert9.db"

  test_contains "$firefox_text" "$(run -install)"
}

it_prints_java_standalone_install_text() {
  test_contains "The local CA is now installed in Java's trust store! ☕️" \
    "$(TRUST_STORES="java" run -install)"
}

if [ "$(uname -s)" = "Linux" ]; then

  it_prints_localCA_already_installed_in_java_text() {
    test_contains "The local CA is already installed in Java's trust store! 👍" \
      "$(run -install)"
  }

fi

it_prints_keytool_not_available_warning() {
  test_contains "Warning: \"keytool\" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️" \
    "$(JAVA_HOME="/dev/null" TRUST_STORES="java" run -install)"
}

it_adds_mkcert_to_java_cacerts() {
  if [ "$(uname -s)" = "Linux" ]; then
    local cacerts="$JAVA_HOME/lib/security/cacerts"
  else
    local cacerts="$JAVA_HOME/jre/lib/security/cacerts"
  fi


  ! echo "$(keytool -list -keystore "$cacerts" -storepass changeit)" | \
    grep 'mkcert'

  run -install
  echo "$(keytool -list -keystore "$cacerts" -storepass changeit)" | \
    grep 'mkcert'
}

it_prints_install_uninstall_error() {
  test_contains "ERROR: you can't set -install and -uninstall at the same time" \
    "$(run -install -uninstall)"
}

it_prints_CAROOT_flag_error() {
  test_contains "ERROR: you can't set -\[un\]install and -CAROOT at the same time" \
    "$(run -install -CAROOT "$CAROOT"uuu)"
}

it_prints_mkdir_CAROOT_error() {
  CAROOT=/dev/null/bad-caroot

  test_contains "ERROR: failed to create the CAROOT: mkdir " \
    "$(run -install)"
}

it_prints_certutil_error() {
  setup_nss
  stub_cmd certutil -A -d

  test_contains "ERROR: failed to execute \"certutil -A -d sql:$NSSDB\": exit status 42" \
    "$(run -install)"
}

it_prints_keytool_error() {
  stub_cmd keytool -importcert -noprompt

  test_contains "ERROR: failed to execute \"keytool -importcert\": exit status 42" \
    "$(JAVA_HOME="$(stub_java_home)" TRUST_STORES="java" run -install)"
}

if [ "$(uname -s)" = "Linux" ]; then
  it_prints_firefox_unsupported_note() {
    setup_nss

    test_contains "Note: $NSS_BROWSERS support is not available on your platform. ℹ️" \
      "$(PATH="" TRUST_STORES="nss" run -install)"
  }

  it_prints_certutil_missing_warning() {
    local warning="$(cat <<WARNING
  Warning: "certutil" is not available, so the CA can\'t be automatically installed in $NSS_BROWSERS! ⚠️
  Install "certutil" with "$INSTALL_CERTUTIL" and re-run "mkcert -install" 👈
WARNING
)"

    setup_nss
    if [ "$(uname -s)" = "Linux" ]; then
      stub_cmd apt
    else
      stub_cmd brew --prefix nss
    fi

    test_contains "$warning" "$(PATH="$STUBS_PATH" TRUST_STORES="nss" run -install)"
  }

  it_prints_sudo_not_available_warning() {
    local nobody_dir="$(setuid nobody mktemp -d -t mkcert.nobody_dir.XXXXX)"

    go build -o "$nobody_dir/mkcert" ./

    test_contains "Warning: \"sudo\" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️" \
      "$(PATH="$STUBS_PATH" CAROOT="$nobody_dir" $(which setuid) nobody "$nobody_dir/mkcert" -install 2>&1)"
  }

  it_prints_missing_system_trust_text() {
    local want="$(cat <<WARNING
  Installing to the system store is not yet supported on this Linux 😣 but $NSS_BROWSERS will still work.
  You can also manually install the root certificate at "$CAROOT/rootCA.pem".
WARNING
)"
    local chroot_dir="$(mktemp -d -t mkcert.chroot.XXXXX)"

    CGO_ENABLED=0 go build -o "$chroot_dir/mkcert" ./

    test_contains "$want" "$(chroot "$chroot_dir" ./mkcert -install 2>&1)"
  }
fi

it_prints_localCA_already_installed_in_nss_text() {
  setup_nss
  TRUST_STORES="nss" mkcert -install

  test_contains "The local CA is already installed in the $NSS_BROWSERS trust store! 👍" \
    "$(TRUST_STORES="nss" run -install)"
}

it_prints_localCA_already_installed_in_system_text() {
  setup_nss
  TRUST_STORES="system" mkcert -install

  test_contains "The local CA is already installed in the system trust store! 👍" \
    "$(TRUST_STORES="system" run -install)"
}

