#!/usr/bin/env bash
# Builds the TailConnect Android app (an APK) with the Android SDK's own
# tools: no Gradle, no NDK, no libraries beyond the Android framework.
#
#   android/build.sh                      # → android/build/tailconnect.apk
#   android/build.sh install              # … and install it on the connected device (adb)
#
# Needs: Go, a JDK (17+), and the Android SDK with build-tools and a platform.
# Found via $JAVA_HOME and $ANDROID_HOME, defaulting to ~/Android/{jdk,Sdk}.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SDK=${ANDROID_HOME:-$HOME/Android/Sdk}
export JAVA_HOME=${JAVA_HOME:-$HOME/Android/jdk}
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
PLATFORM=$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar
ADB=$SDK/platform-tools/adb
VERSION=${VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)}
# Android needs an increasing integer version: minutes since 2026-01-01.
VERSION_CODE=${VERSION_CODE:-$(( ($(date +%s) - 1767225600) / 60 ))}
MIN_SDK=29
TARGET_SDK=33
OUT=$HERE/build
KEYSTORE=${KEYSTORE:-$HOME/.android/tailconnect-debug.keystore}

for t in "$BT/aapt2" "$BT/d8" "$BT/zipalign" "$BT/apksigner" "$JAVA_HOME/bin/javac" "$PLATFORM"; do
	[[ -e $t ]] || { echo "missing: $t (set ANDROID_HOME / JAVA_HOME)" >&2; exit 1; }
done
export PATH=$JAVA_HOME/bin:$PATH

echo "== tailconnect $VERSION ($VERSION_CODE), $(basename "$(dirname "$PLATFORM")"), build-tools $(basename "$BT")"
rm -rf "${OUT:?}"
mkdir -p "$OUT"/{gen,classes,dex,apk/lib/arm64-v8a}

echo "== Go daemon (libtcd.so)"
(cd "$ROOT" && GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
	-ldflags "-s -w -X main.version=$VERSION" -o "$OUT/apk/lib/arm64-v8a/libtcd.so" ./cmd/tcd-android)

echo "== resources"
"$BT/aapt2" compile --dir "$HERE/res" -o "$OUT/res.zip"
"$BT/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" --java "$OUT/gen" \
	--min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK \
	--version-code "$VERSION_CODE" --version-name "$VERSION" \
	-o "$OUT/base.apk" "$OUT/res.zip"

echo "== Java"
javac -nowarn -source 17 -target 17 -encoding UTF-8 -classpath "$PLATFORM" -d "$OUT/classes" \
	$(find "$HERE/src" "$OUT/gen" -name '*.java') 2>&1 | grep -v "bootstrap class path\|^1 warning$" || true
[[ -n $(find "$OUT/classes" -name '*.class') ]] || { echo "javac failed" >&2; exit 1; }
"$BT/d8" --release --min-api $MIN_SDK --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

echo "== APK"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
(cd "$OUT/apk" && zip -q -r "$OUT/unsigned.apk" lib)
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
if [[ ! -f $KEYSTORE ]]; then
	echo "== creating a signing key: $KEYSTORE (keep it: updates must be signed with the same key)"
	mkdir -p "$(dirname "$KEYSTORE")"
	keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android -alias tailconnect \
		-keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=TailConnect" >/dev/null 2>&1
fi
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android --ks-key-alias tailconnect \
	--out "$OUT/tailconnect.apk" "$OUT/aligned.apk"
rm -f "$OUT"/{unsigned,aligned,base}.apk "$OUT/res.zip"
ls -la "$OUT/tailconnect.apk"

if [[ ${1:-} == install ]]; then
	echo "== installing on $("$ADB" get-serialno)"
	"$ADB" install --no-incremental -r "$OUT/tailconnect.apk"
fi
