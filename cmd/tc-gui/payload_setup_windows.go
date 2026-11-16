//go:build setup

package main

import _ "embed"

// setupPayload is the Windows package zip (make dist-windows copies it here
// as setup-payload.zip before building the installer).
//
//go:embed setup-payload.zip
var setupPayload []byte
