#!/usr/bin/env roundup

source "$(dirname $1)/common.sh"

describe "mkcert"

after() {
  cleanup
}

it_outputs_default_text() {
  test "$(run)" = "$(mkcert)"
}

it_outputs_generate_text() {
  install
  setup_nss
  local want="$(mkcert example.org)"
  cleanup
  install
  setup_nss

  test "$(run example.org)" = "$want"
}

it_outputs_uninstalled_generate_text() {
  setup_nss
  local want="$(mkcert example.org)"
  cleanup
  setup_nss

  test "$(run example.org)" = "$want"
}

it_generates_a_cert_and_key() {
  local want="$(cat <<OUTPUT
Created a new certificate valid for the following names 📜
 - "example.org"

The certificate is at "./example.org.pem" and the key at "./example.org-key.pem" ✅

It will expire on
OUTPUT
)"

  install
  ! test -f "example.org.pem"
  ! test -f "example.org-key.pem"

  test_contains "$want" "$(run example.org)"
  test -f "example.org.pem"
  test -f "example.org-key.pem"
}

it_prints_install_warnings() {
  if [ "$(uname -s)" = "Linux" ]; then
    local warning="$(cat <<OUTPUT
Created a new local CA 💥
Note: the local CA is not installed in the system trust store.
Note: the local CA is not installed in the Firefox and/or Chrome/Chromium trust store.
Note: the local CA is not installed in the Java trust store.
Run "mkcert -install" for certificates to be trusted automatically ⚠️
OUTPUT
)"
  else
    local warning="$(cat <<OUTPUT
Created a new local CA 💥
Note: the local CA is not installed in the system trust store.
Note: the local CA is not installed in the Firefox trust store.
Note: the local CA is not installed in the Java trust store.
Run "mkcert -install" for certificates to be trusted automatically ⚠️
OUTPUT
)"
  fi

  setup_nss

  test_contains "$warning" "$(run example.org)"
}

it_prints_ca_key_missing_error() {
  install
  unlink "$CAROOT/rootCA-key.pem"

  test_contains "ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing" \
    "$(run example.org)"
}

it_prints_invalid_name_error() {
  local want='ERROR: "!" is not a valid hostname, IP, URL or email'

  install

  test_contains "$want" "$(run '!')"
}

it_prints_invalid_CA_cert_error() {
  touch "$CAROOT/rootCA.pem"

  test_contains "ERROR: failed to read the CA certificate: unexpected content" \
    "$(run example.com)"
}

it_prints_invalid_CA_key_error() {
  install
  unlink "$CAROOT/rootCA-key.pem"
  > "$CAROOT/rootCA-key.pem"

  test_contains "ERROR: failed to read the CA key: unexpected content" \
    "$(run example.com)"
}

it_prints_create_CAROOT_failed_error() {
  CAROOT=/dev/null/bad-caroot

  test_contains "ERROR: failed to create the CAROOT: " \
    "$(run example.com)"
}

it_prints_keytool_error() {
  stub_cmd keytool -list -keystore

  test_contains "ERROR: failed to execute \"keytool -list\": exit status 42" \
    "$(JAVA_HOME="$(stub_java_home)" TRUST_STORES="java" run example.org)"
}
