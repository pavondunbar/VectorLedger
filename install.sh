#!/usr/bin/env bash
# install.sh — VectorLedger installer
#
# Usage (one-liner):
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
#
# Options (set as environment variables before piping to bash):
#   VLEDGER_VERSION   — specific release tag to install, e.g. "v0.1.0"
#                       (default: latest release from GitHub)
#   VLEDGER_INSTALL_DIR — directory to install the binary into
#                       (default: /usr/local/bin, falls back to ~/.local/bin)
#   VLEDGER_NO_MODIFY_PATH — set to "1" to skip adding install dir to PATH
#
# Examples:
#   # Install latest release
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
#
#   # Install a specific version
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh \
#     | VLEDGER_VERSION=v0.1.0 bash
#
#   # Install to a custom directory
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh \
#     | VLEDGER_INSTALL_DIR="$HOME/.local/bin" bash

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

REPO="pavondunbar/VectorLedger"
BINARY="vledger"
RELEASES_API="https://api.github.com/repos/${REPO}/releases/latest"
RELEASES_DOWNLOAD="https://github.com/${REPO}/releases/download"

# ── Colour output helpers ─────────────────────────────────────────────────────

# Detect whether the terminal supports colour
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6)
    BOLD=$(tput bold)
    RESET=$(tput sgr0)
else
    RED="" GREEN="" YELLOW="" CYAN="" BOLD="" RESET=""
fi

info()    { printf "%s  info%s  %s\n"  "${CYAN}"   "${RESET}" "$*"; }
success() { printf "%s    ok%s  %s\n"  "${GREEN}"  "${RESET}" "$*"; }
warn()    { printf "%s  warn%s  %s\n"  "${YELLOW}" "${RESET}" "$*"; }
error()   { printf "%s error%s  %s\n"  "${RED}"    "${RESET}" "$*" >&2; }
bold()    { printf "%s%s%s\n"          "${BOLD}"   "$*"        "${RESET}"; }
die()     { error "$*"; exit 1; }

# ── Platform detection ────────────────────────────────────────────────────────

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux)  os="linux"  ;;
        Darwin) os="macos"  ;;
        *)      die "Unsupported operating system: $(uname -s). VectorLedger supports Linux and macOS." ;;
    esac

    case "$(uname -m)" in
        x86_64 | amd64)  arch="x86_64"  ;;
        arm64  | aarch64) arch="aarch64" ;;
        *) die "Unsupported architecture: $(uname -m). Supported: x86_64, aarch64." ;;
    esac

    echo "${os}-${arch}"
}

# ── Dependency checks ─────────────────────────────────────────────────────────

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "Required command not found: $1. Please install it and try again."
    fi
}

# ── Version resolution ────────────────────────────────────────────────────────

resolve_version() {
    local version="${VLEDGER_VERSION:-}"

    if [ -n "$version" ]; then
        # Normalise: ensure it starts with 'v'
        [[ "$version" == v* ]] || version="v${version}"
        echo "$version"
        return
    fi

    info "Fetching latest release version from GitHub..."

    local raw=""
    if command -v curl >/dev/null 2>&1; then
        raw=$(curl --proto '=https' --tlsv1.2 -sSf \
            --max-time 10 \
            -H "Accept: application/vnd.github+json" \
            "${RELEASES_API}" 2>/dev/null || true)
    elif command -v wget >/dev/null 2>&1; then
        raw=$(wget -qO- --timeout=10 \
            --header "Accept: application/vnd.github+json" \
            "${RELEASES_API}" 2>/dev/null || true)
    else
        die "Neither curl nor wget is available. Please install one and try again."
    fi

    # Check for API errors (rate limit, 404, etc.)
    if echo "$raw" | grep -q '"message"'; then
        local api_msg
        api_msg=$(echo "$raw" | grep '"message"' | head -1 | sed 's/.*"message": *"\([^"]*\)".*/\1/')
        warn "GitHub API returned an error: ${api_msg}"
        die "Could not determine the latest release version.

  This usually means:
    1. The GitHub Actions release workflow is still running (wait ~10 minutes
       after pushing a tag, then try again), or
    2. No GitHub Release has been published yet for this repository.

  Fix: set VLEDGER_VERSION explicitly:
    curl --proto '=https' --tlsv1.2 -sSf \\
      https://raw.githubusercontent.com/${REPO}/main/install.sh \\
      | VLEDGER_VERSION=v1.0.0 bash"
    fi

    version=$(echo "$raw" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [ -z "$version" ]; then
        die "Could not determine the latest release version.

  This usually means the GitHub Actions release workflow has not finished yet.
  Wait a few minutes after pushing a version tag, then retry.

  Or set the version explicitly:
    curl --proto '=https' --tlsv1.2 -sSf \\
      https://raw.githubusercontent.com/${REPO}/main/install.sh \\
      | VLEDGER_VERSION=v1.0.0 bash"
    fi

    echo "$version"
}

# ── Install directory resolution ──────────────────────────────────────────────

resolve_install_dir() {
    local dir="${VLEDGER_INSTALL_DIR:-}"

    if [ -n "$dir" ]; then
        echo "$dir"
        return
    fi

    # Prefer /usr/local/bin if we can write to it (or become root)
    if [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    elif command -v sudo >/dev/null 2>&1; then
        echo "/usr/local/bin"
    else
        warn "/usr/local/bin is not writable and sudo is not available. Installing to ~/.local/bin instead."
        echo "${HOME}/.local/bin"
    fi
}

# ── Download helpers ──────────────────────────────────────────────────────────

download() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSfL --progress-bar \
            --output "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -q --show-progress \
            -O "$dest" "$url"
    else
        die "Neither curl nor wget is available. Please install one and try again."
    fi
}

# ── Checksum verification ─────────────────────────────────────────────────────

verify_checksum() {
    local archive="$1"
    local checksum_file="$2"

    if command -v sha256sum >/dev/null 2>&1; then
        # sha256sum format: "<hash>  <filename>"
        # Filter to only the line matching our archive filename
        local expected
        expected=$(grep "$(basename "$archive")" "$checksum_file" | awk '{print $1}')
        if [ -z "$expected" ]; then
            warn "No checksum entry found for $(basename "$archive") — skipping verification."
            return 0
        fi
        local actual
        actual=$(sha256sum "$archive" | awk '{print $1}')
        if [ "$expected" != "$actual" ]; then
            die "Checksum mismatch for $(basename "$archive")!\n  Expected : $expected\n  Actual   : $actual"
        fi
    elif command -v shasum >/dev/null 2>&1; then
        # macOS ships shasum instead of sha256sum
        local expected
        expected=$(grep "$(basename "$archive")" "$checksum_file" | awk '{print $1}')
        if [ -z "$expected" ]; then
            warn "No checksum entry found for $(basename "$archive") — skipping verification."
            return 0
        fi
        local actual
        actual=$(shasum -a 256 "$archive" | awk '{print $1}')
        if [ "$expected" != "$actual" ]; then
            die "Checksum mismatch for $(basename "$archive")!\n  Expected : $expected\n  Actual   : $actual"
        fi
    else
        warn "sha256sum / shasum not found — skipping checksum verification."
        return 0
    fi

    success "Checksum verified."
}

# ── PATH advice ───────────────────────────────────────────────────────────────

add_to_path_advice() {
    local install_dir="$1"

    # If the directory is already in PATH, nothing to do
    case ":${PATH}:" in
        *":${install_dir}:"*) return ;;
    esac

    if [ "${VLEDGER_NO_MODIFY_PATH:-0}" = "1" ]; then
        warn "${install_dir} is not in your PATH."
        warn "Add it manually: export PATH=\"${install_dir}:\$PATH\""
        return
    fi

    # Detect the user's shell profile file
    local profile_file=""
    case "${SHELL:-}" in
        */zsh)  profile_file="${ZDOTDIR:-$HOME}/.zshrc" ;;
        */bash)
            if [ -f "${HOME}/.bash_profile" ]; then
                profile_file="${HOME}/.bash_profile"
            else
                profile_file="${HOME}/.bashrc"
            fi
            ;;
        */fish) profile_file="${HOME}/.config/fish/config.fish" ;;
        *)
            warn "Could not detect your shell. Add ${install_dir} to your PATH manually."
            return
            ;;
    esac

    local export_line
    if [[ "${SHELL:-}" == */fish ]]; then
        export_line="fish_add_path ${install_dir}"
    else
        export_line="export PATH=\"${install_dir}:\$PATH\""
    fi

    printf '\n# VectorLedger\n%s\n' "${export_line}" >> "${profile_file}"
    warn "${install_dir} was not in your PATH."
    warn "Added to ${profile_file}. Restart your shell or run:"
    warn "  source ${profile_file}"
}

# ── Build from source fallback ────────────────────────────────────────────────

build_from_source() {
    local install_dir="$1"
    local version="$2"

    warn "No pre-built binary found for this platform. Attempting to build from source..."

    require_cmd cargo
    require_cmd git

    local rust_version
    rust_version=$(rustc --version 2>/dev/null | awk '{print $2}')
    info "Rust version: ${rust_version}"

    # Initialise tmpdir immediately so the EXIT trap can always clean it up,
    # even if a subsequent command exits early.
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    info "Cloning repository at ${version}..."
    git clone --depth 1 --branch "${version}" \
        "https://github.com/${REPO}.git" "${tmpdir}/vectorledger" \
        2>&1 | tail -2

    info "Building release binary (this may take a few minutes)..."
    # Build only the vledger binary package — not the entire workspace.
    # The workspace contains internal-only tools that are not present in
    # customer-facing releases.
    cargo build --release \
        --manifest-path "${tmpdir}/vectorledger/Cargo.toml" \
        --package vledger

    install_binary "${tmpdir}/vectorledger/target/release/${BINARY}" "$install_dir"
}

# ── Binary installation ───────────────────────────────────────────────────────

install_binary() {
    local src="$1"
    local install_dir="$2"

    mkdir -p "$install_dir"

    if [ -w "$install_dir" ]; then
        install -m 755 "$src" "${install_dir}/${BINARY}"
    elif command -v sudo >/dev/null 2>&1; then
        info "Writing to ${install_dir} requires sudo..."
        sudo install -m 755 "$src" "${install_dir}/${BINARY}"
    else
        die "Cannot write to ${install_dir} and sudo is not available. Set VLEDGER_INSTALL_DIR to a directory you own."
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    bold ""
    bold "  VectorLedger Installer"
    bold "  VectorGuard Labs — https://vectorguardlabs.com"
    bold ""

    require_cmd uname

    local platform version install_dir
    platform=$(detect_platform)
    version=$(resolve_version)
    install_dir=$(resolve_install_dir)

    info "Platform      : ${platform}"
    info "Version       : ${version}"
    info "Install dir   : ${install_dir}"

    # ── Construct expected asset name ────────────────────────────────────
    # Expected release asset naming convention:
    #   vledger-<version>-<os>-<arch>.tar.gz
    # e.g. vledger-v0.1.0-linux-x86_64.tar.gz
    local asset_name="${BINARY}-${version}-${platform}.tar.gz"
    local checksum_name="${BINARY}-${version}-checksums.txt"
    local asset_url="${RELEASES_DOWNLOAD}/${version}/${asset_name}"
    local checksum_url="${RELEASES_DOWNLOAD}/${version}/${checksum_name}"

    # ── Download to a temp directory ─────────────────────────────────────
    # Initialise tmpdir before anything else so the EXIT trap always fires
    # cleanly even if a download or extraction step exits early.
    local tmpdir
    tmpdir=$(mktemp -d)
    # Always clean up on exit
    trap 'rm -rf "$tmpdir"' EXIT

    local archive="${tmpdir}/${asset_name}"
    local checksum_file="${tmpdir}/${checksum_name}"

    info "Downloading ${asset_name}..."
    if ! download "$asset_url" "$archive" 2>/dev/null; then
        warn "Pre-built binary not available for ${platform} at ${version}."
        build_from_source "$install_dir" "$version"
        return
    fi

    # ── Verify checksum (best-effort) ─────────────────────────────────────
    info "Verifying checksum..."
    if download "$checksum_url" "$checksum_file" 2>/dev/null; then
        verify_checksum "$archive" "$checksum_file"
    else
        warn "Checksum file not available — skipping verification."
    fi

    # ── Extract ───────────────────────────────────────────────────────────
    info "Extracting archive..."
    tar -xzf "$archive" -C "$tmpdir"

    # The binary may be at the root of the archive or inside a subdirectory
    local binary_path
    binary_path=$(find "$tmpdir" -type f -name "$BINARY" ! -name "*.tar.gz" | head -1)
    if [ -z "$binary_path" ]; then
        die "Could not find '${BINARY}' binary inside the downloaded archive."
    fi
    chmod +x "$binary_path"

    # ── Install ───────────────────────────────────────────────────────────
    info "Installing ${BINARY} to ${install_dir}..."
    install_binary "$binary_path" "$install_dir"

    # ── Verify ────────────────────────────────────────────────────────────
    local installed_version
    installed_version=$("${install_dir}/${BINARY}" --version 2>/dev/null || true)
    success "Installed: ${install_dir}/${BINARY}  (${installed_version})"

    # ── PATH ──────────────────────────────────────────────────────────────
    add_to_path_advice "$install_dir"

    bold ""
    bold "  VectorLedger ${version} is ready."
    bold ""
    bold "  Quick start (requires PyHSM daemon running first):"
    printf "    vledger init --key-source pyhsm\n"
    printf "    vledger start --data-dir ./vledger-data\n"
    bold ""
    bold "  Full setup guide: https://github.com/${REPO}#quick-start"
    bold ""
}

main "$@"
