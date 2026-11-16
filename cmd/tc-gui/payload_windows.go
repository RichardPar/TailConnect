//go:build !setup

package main

// setupPayload is empty in the app; the installer build (-tags setup)
// embeds the package.
var setupPayload []byte
