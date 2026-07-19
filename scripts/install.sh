#!/usr/bin/env sh
set -eu

REPO="${PASTEVAULT_INSTALL_REPO:-arc53/pastevault}"
VERSION="${PASTEVAULT_INSTALL_VERSION:-latest}"
INSTALL_DIR="${PASTEVAULT_INSTALL_DIR:-$HOME/.local/bin}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux) echo "linux" ;;
    *)
      echo "Unsupported operating system: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    arm64|aarch64) echo "arm64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

checksum_file() {
  archive_path="$1"
  checksums_path="$2"

  expected="$(grep " $(basename "$archive_path")\$" "$checksums_path" | awk '{print $1}')"
  if [ -z "$expected" ]; then
    echo "Failed to find checksum for $(basename "$archive_path")" >&2
    exit 1
  fi

  if command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
  elif command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive_path" | awk '{print $1}')"
  else
    echo "Missing checksum tool: install shasum or sha256sum" >&2
    exit 1
  fi

  if [ "$expected" != "$actual" ]; then
    echo "Checksum verification failed for $(basename "$archive_path")" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd tar

OS="$(detect_os)"
ARCH="$(detect_arch)"
ARCHIVE_NAME="pastevault_${OS}_${ARCH}.tar.gz"
CHECKSUMS_NAME="checksums.txt"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

if [ "$VERSION" = "latest" ]; then
  ARCHIVE_URL="https://github.com/${REPO}/releases/latest/download/${ARCHIVE_NAME}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/latest/download/${CHECKSUMS_NAME}"
else
  ARCHIVE_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/${CHECKSUMS_NAME}"
fi

ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
CHECKSUMS_PATH="${TMP_DIR}/${CHECKSUMS_NAME}"

echo "Downloading ${ARCHIVE_NAME}..."
curl -fsSL "$ARCHIVE_URL" -o "$ARCHIVE_PATH"
curl -fsSL "$CHECKSUMS_URL" -o "$CHECKSUMS_PATH"

checksum_file "$ARCHIVE_PATH" "$CHECKSUMS_PATH"

mkdir -p "$INSTALL_DIR"
tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
install -m 0755 "${TMP_DIR}/pastevault" "${INSTALL_DIR}/pastevault"

echo "Installed pastevault to ${INSTALL_DIR}/pastevault"
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "Add ${INSTALL_DIR} to your PATH to run 'pastevault' directly." >&2
    ;;
esac
