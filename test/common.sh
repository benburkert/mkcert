#!/bin/sh

if [ -n "$DEBUG" ]; then
  set -x
fi

export CAROOT="${TEST_CAROOT:=$(mktemp -d -t mkcert.caroot.XXXXX)}"

test_home="${TEST_HOME:=$(mktemp -d -t mkcert.home.XXXXX)}"
export HOME="$test_home"
export NSSDB="$test_home/.pki/nssdb"

test_stubs="${TEST_STUBS:=$(mktemp -d -t mkcert.stubs.XXXXX)}"
export STUBS_PATH="$test_stubs"
export PATH="$STUBS_PATH:$PATH"

if [ "$(uname -s)" = "Linux" ]; then
  export NSS_BROWSERS="Firefox and/or Chrome/Chromium"
  export INSTALL_CERTUTIL="apt install libnss3-tools"
else
  export NSS_BROWSERS="Firefox"
  export INSTALL_CERTUTIL="brew install nss"
fi

cleanup() {
  mkcert -uninstall 2>/dev/null || true

  { test -f "$CAROOT/rootCA.pem" && unlink "$CAROOT/rootCA.pem" ; } || true
  { test -f "$CAROOT/rootCA-key.pem" && unlink "$CAROOT/rootCA-key.pem" ; } || true
  { test -d "$test_home/.pki" && rm -r "$test_home/.pki" ; } || true
  { test -f "$test_stubs/*" && rm "$test_stubs/*" ; } || true

  { test -f "./*.pem" && rm "./*.pem" ; } || true
}

install() {
  mkcert -install 2>/dev/null
}

mkcert_bin="$(which mkcert)"
mkcert() {
  $mkcert_bin $@ 2>&1
}

go_bin="$(which go)"
run() {
  $go_bin run ./ $@ 2>&1
}

setup_nss() {
  mkdir -p "$NSSDB"
  certutil -d "$NSSDB" -N --empty-password
}

stub_cmd() {
  local cmd="$1"
  local full_cmd="$(which $cmd)"
  shift
  local argv="$@"

  cat <<STUB >"$test_stubs/$cmd"
#!/usr/bin/env bash

if [[ "\$@" == \$(printf %q '$argv')* ]]; then
  unlink \$0
  exit 42
fi

exec $full_cmd "\$@"
STUB

  chmod +x "$test_stubs/$cmd"
}

stub_java_home() {
  local java_home="$(mktemp -d -t mkcert.java_home.XXXXX)"

  mkdir "$java_home/bin"
  ln -s "$(which keytool)" "$java_home/bin/keytool"
  ln -s "$JAVA_HOME/lib" "$java_home/lib"
  ln -s "$JAVA_HOME/jre" "$java_home/jre"

  echo "$java_home"
}

test_contains() {
  [ -z "$1" ] || { [ -z "${2##*$1*}" ] && [ -n "$2" ]; }
}
