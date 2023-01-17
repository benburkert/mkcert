#!/usr/bin/env roundup

source "$(dirname $1)/common.sh"

describe "mkcert -help"

it_outputs_help_text() {
  test "$(run -help)" = "$(mkcert -help)"
}
