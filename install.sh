#!/usr/bin/env bash

# install.sh — VectorLedger installer
#
# Usage (one-liner):
#   curl --proto '=https' --tlsv1.2 -sSf \
#     https://raw.githubusercontent.com/pavondunbar/VectorLedger/main/install.sh | bash
#
# Options (set as environment variables before piping to bash):
#   VLEDGER_VERSION       — specific release tag to install, e.g. "v1.0.0"
#                           (default: latest release from GitHub)
#                           NOTE: if the GitHub API is rate-limited or unreachable,
#                           you must supply this explicitly.
#   VLEDGER_INSTALL_DIR   — directory to install the binary into
#                           (default: /usr/local/bin, falls back to ~/.local/bin)
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
#     | VLEDGER_VERSION=v1.0.0 bash
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

# Fallback used when the GitHub Releases API cannot determine the latest version.
# Update this whenever a new release is cut.
LATEST_KNOWN_VERSION=""

# ── Colour output helpers ─────────────────────────────────────────────────────

if [ -t 1 ] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6)
    BOLD=$(tput bold)
    RESET=$(tput sgr0)
else
    RED=""
    GREEN=""
    YELLOW=""
    CYAN=""
    BOLD=""
    RESET=""
fi

# IMPORTANT:
# All logging goes to stderr so command substitution such as:
#
#   version=$(resolve_version)
#
# captures ONLY the actual return value from stdout.

info() {
    printf "%s  info%s  %s\n" "${CYAN}" "${RESET}" "$*" >&2
}

success() {
    printf "%s    ok%s  %s\n" "${GREEN}" "${RESET}" "$*" >&2
}

warn() {
    printf "%s  warn%s  %s\n" "${YELLOW}" "${RESET}" "$*" >&2
}

error() {
    printf "%s error%s  %s\n" "${RED}" "${RESET}" "$*" >&2
}

bold() {
    printf "%s%s%s\n" "${BOLD}" "$*" "${RESET}"
}

die() {
    error "$*"
    exit 1
}

# ── Platform detection ────────────────────────────────────────────────────────

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux)
            os="linux"
            ;;
        Darwin)
            os="macos"
            ;;
        *)
            die "Unsupported operating system: $(uname -s). VectorLedger supports Linux and macOS."
            ;;
    esac

    case "$(uname -m)" in
        x86_64 | amd64)
            arch="x86_64"
            ;;
        arm64 | aarch64)
            arch="aarch64"
            ;;
        *)
            die "Unsupported architecture: $(uname -m). Supported: x86_64, aarch64."
            ;;
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

    # Explicit version supplied by the user.
    if [ -n "$version" ]; then
        [[ "$version" == v* ]] || version="v${version}"
        echo "$version"
        return 0
    fi

    info "Fetching latest release version from GitHub..."

    local raw=""

    if command -v curl >/dev/null 2>&1; then
        raw=$(
            curl \
                --proto '=https' \
                --tlsv1.2 \
                -fsSL \
                --max-time 10 \
                -H "Accept: application/vnd.github+json" \
                -H "User-Agent: VectorLedger-Installer" \
                "${RELEASES_API}" \
                2>/dev/null || true
        )
    elif command -v wget >/dev/null 2>&1; then
        raw=$(
            wget \
                -qO- \
                --timeout=10 \
                --header="Accept: application/vnd.github+json" \
                --header="User-Agent: VectorLedger-Installer" \
                "${RELEASES_API}" \
                2>/dev/null || true
        )
    else
        die "Neither curl nor wget is available. Please install one and try again."
    fi

    # If the API returned an error, fall back safely.
    if [ -z "$raw" ]; then
        if [ -n "${LATEST_KNOWN_VERSION:-}" ]; then
            warn "Could not reach the GitHub Releases API. Falling back to ${LATEST_KNOWN_VERSION}."
            echo "$LATEST_KNOWN_VERSION"
        else
            error "Could not reach the GitHub Releases API and no fallback version is set."
            error "Please specify a version explicitly:"
            error "  curl ... | VLEDGER_VERSION=<version> bash"
            error "Or check available releases at: https://github.com/${REPO}/releases"
            exit 1
        fi
        return 0
    fi

    if echo "$raw" | grep -q '"message"'; then
        local api_msg

        api_msg=$(
            echo "$raw" |
                grep '"message"' |
                head -1 |
                sed 's/.*"message": *"\([^"]*\)".*/\1/'
        )

        if [ -n "${LATEST_KNOWN_VERSION:-}" ]; then
            warn "GitHub API returned: ${api_msg}. Falling back to ${LATEST_KNOWN_VERSION}."
            echo "$LATEST_KNOWN_VERSION"
        else
            error "GitHub API returned: ${api_msg}"
            error "Please specify a version explicitly:"
            error "  curl ... | VLEDGER_VERSION=<version> bash"
            error "Or check available releases at: https://github.com/${REPO}/releases"
            exit 1
        fi
        return 0
    fi

    version=$(
        echo "$raw" |
            grep '"tag_name"' |
            head -1 |
            sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
    )

    if [ -z "$version" ]; then
        if [ -n "${LATEST_KNOWN_VERSION:-}" ]; then
            warn "Could not determine latest release from GitHub API. Falling back to ${LATEST_KNOWN_VERSION}."
            echo "$LATEST_KNOWN_VERSION"
        else
            error "Could not determine latest release from GitHub API."
            error "Please specify a version explicitly:"
            error "  curl ... | VLEDGER_VERSION=<version> bash"
            error "Or check available releases at: https://github.com/${REPO}/releases"
            exit 1
        fi
        return 0
    fi

    echo "$version"
}

# ── Install directory resolution ──────────────────────────────────────────────

resolve_install_dir() {
    local dir="${VLEDGER_INSTALL_DIR:-}"

    if [ -n "$dir" ]; then
        echo "$dir"
        return 0
    fi

    # Prefer /usr/local/bin if writable or if sudo is available.
    if [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    elif command -v sudo >/dev/null 2>&1; then
        echo "/usr/local/bin"
    else
        warn "/usr/local/bin is not writable and sudo is not available."
        warn "Installing to ~/.local/bin instead."
        echo "${HOME}/.local/bin"
    fi
}

# ── Download helpers ──────────────────────────────────────────────────────────

download() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl \
            --proto '=https' \
            --tlsv1.2 \
            -fsSL \
            --progress-bar \
            --output "$dest" \
            "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget \
            --https-only \
            -q \
            --show-progress \
            -O "$dest" \
            "$url"
    else
        die "Neither curl nor wget is available. Please install one and try again."
    fi
}

# ── Checksum verification ─────────────────────────────────────────────────────

verify_checksum() {
    local archive="$1"
    local checksum_file="$2"
    local expected actual

    if command -v sha256sum >/dev/null 2>&1; then
        expected=$(
            grep -F "$(basename "$archive")" "$checksum_file" |
                awk '{print $1}' |
                head -1
        )

        if [ -z "$expected" ]; then
            warn "No checksum entry found for $(basename "$archive") — skipping verification."
            return 0
        fi

        actual=$(sha256sum "$archive" | awk '{print $1}')

    elif command -v shasum >/dev/null 2>&1; then
        expected=$(
            grep -F "$(basename "$archive")" "$checksum_file" |
                awk '{print $1}' |
                head -1
        )

        if [ -z "$expected" ]; then
            warn "No checksum entry found for $(basename "$archive") — skipping verification."
            return 0
        fi

        actual=$(shasum -a 256 "$archive" | awk '{print $1}')

    else
        warn "sha256sum / shasum not found — skipping checksum verification."
        return 0
    fi

    if [ "$expected" != "$actual" ]; then
        die "Checksum mismatch for $(basename "$archive")!
  Expected : $expected
  Actual   : $actual"
    fi

    success "Checksum verified."
}

# ── PATH advice ───────────────────────────────────────────────────────────────

add_to_path_advice() {
    local install_dir="$1"

    case ":${PATH}:" in
        *":${install_dir}:"*)
            return
            ;;
    esac

    if [ "${VLEDGER_NO_MODIFY_PATH:-0}" = "1" ]; then
        warn "${install_dir} is not in your PATH."
        warn "Add it manually: export PATH=\"${install_dir}:\$PATH\""
        return
    fi

    local profile_file=""

    case "${SHELL:-}" in
        */zsh)
            profile_file="${ZDOTDIR:-$HOME}/.zshrc"
            ;;
        */bash)
            if [ -f "${HOME}/.bash_profile" ]; then
                profile_file="${HOME}/.bash_profile"
            else
                profile_file="${HOME}/.bashrc"
            fi
            ;;
        */fish)
            profile_file="${HOME}/.config/fish/config.fish"
            ;;
        *)
            warn "Could not detect your shell."
            warn "Add ${install_dir} to your PATH manually."
            return
            ;;
    esac

    local export_line

    if [[ "${SHELL:-}" == */fish ]]; then
        export_line="fish_add_path ${install_dir}"
    else
        export_line="export PATH=\"${install_dir}:\$PATH\""
    fi

    # Avoid adding duplicate VectorLedger PATH entries.
    if ! grep -Fq "# VectorLedger" "${profile_file}" 2>/dev/null; then
        printf '\n# VectorLedger\n%s\n' "${export_line}" >> "${profile_file}"
    fi

    warn "${install_dir} was not in your PATH."
    warn "Added to ${profile_file}. Restart your shell or run:"
    warn "  source ${profile_file}"
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
        die "Cannot write to ${install_dir} and sudo is not available.
Set VLEDGER_INSTALL_DIR to a directory you own."
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    bold ""
    bold "  VectorLedger Installer"
    bold "  VectorGuard Labs — https://vectorguardlabs.com"
    bold ""

    require_cmd uname
    require_cmd tar
    require_cmd mktemp

    local platform version install_dir

    platform=$(detect_platform)

    # resolve_version runs in a subshell via $(); exit 1 inside only kills
    # the subshell, not this script.  Capture output then check it is non-empty.
    version=$(resolve_version) || true
    if [ -z "${version:-}" ]; then
        # Error messages were already printed inside resolve_version.
        exit 1
    fi

    install_dir=$(resolve_install_dir)

    info "Platform      : ${platform}"
    info "Version       : ${version}"
    info "Install dir   : ${install_dir}"

    # ── Construct expected asset names ────────────────────────────────────────
    #
    # Expected release asset naming convention:
    #
    #   vledger-<version>-<os>-<arch>.tar.gz
    #
    # Example:
    #
    #   vledger-v1.0.0-linux-x86_64.tar.gz

    local asset_name="${BINARY}-${version}-${platform}.tar.gz"
    local checksum_name="${BINARY}-${version}-checksums.txt"

    local asset_url="${RELEASES_DOWNLOAD}/${version}/${asset_name}"
    local checksum_url="${RELEASES_DOWNLOAD}/${version}/${checksum_name}"

    # ── Temporary directory ───────────────────────────────────────────────────

    local tmpdir
    tmpdir=$(mktemp -d)

    trap 'rm -rf "$tmpdir"' EXIT

    local archive="${tmpdir}/${asset_name}"
    local checksum_file="${tmpdir}/${checksum_name}"

    # ── Download binary ───────────────────────────────────────────────────────

    info "Downloading ${asset_name}..."

    if ! download "$asset_url" "$archive" 2>/dev/null; then
        error "No pre-built binary is available for your platform (${platform}) at version ${version}."
        error ""
        error "Expected asset:"
        error "  ${asset_name}"
        error ""
        error "Supported platforms:"
        error "  linux-x86_64"
        error "  linux-aarch64"
        error "  macos-x86_64"
        error "  macos-aarch64"
        error ""
        error "Please check the releases page for available assets:"
        error "  https://github.com/${REPO}/releases/tag/${version}"
        error ""
        error "If you believe this is an error, please open an issue:"
        error "  https://github.com/${REPO}/issues"
        exit 1
    fi

    # ── Verify checksum ───────────────────────────────────────────────────────

    info "Verifying checksum..."

    if download "$checksum_url" "$checksum_file" 2>/dev/null; then
        verify_checksum "$archive" "$checksum_file"
    else
        warn "Checksum file not available — skipping verification."
    fi

    # ── Extract ───────────────────────────────────────────────────────────────

    info "Extracting archive..."

    if ! tar -xzf "$archive" -C "$tmpdir"; then
        die "Failed to extract ${asset_name}."
    fi

    # Binary may be at the root or inside a subdirectory.
    local binary_path

    binary_path=$(
        find "$tmpdir" \
            -type f \
            -name "$BINARY" \
            -not -path "$archive" |
            head -1
    )

    if [ -z "$binary_path" ]; then
        die "Could not find '${BINARY}' binary inside the downloaded archive."
    fi

    chmod +x "$binary_path"

    # ── Install ───────────────────────────────────────────────────────────────

    info "Installing ${BINARY} to ${install_dir}..."

    install_binary "$binary_path" "$install_dir"

    # ── Verify installation ───────────────────────────────────────────────────

    local installed_version

    installed_version=$(
        "${install_dir}/${BINARY}" --version 2>/dev/null || true
    )

    if [ -z "$installed_version" ]; then
        warn "Binary installed, but version verification failed."
    else
        success "Installed: ${install_dir}/${BINARY} (${installed_version})"
    fi

    # ── PATH advice ───────────────────────────────────────────────────────────

    add_to_path_advice "$install_dir"

    bold ""
    bold "  VectorLedger ${version} is ready."
    bold ""

    bold "  Quick start (requires PyHSM daemon running first):"
    printf "    vledger init --key-source pyhsm\n"
    printf "    vledger start --data-dir ./vledger-data\n"

    bold ""
    bold "  Full setup guide:"
    bold "  https://github.com/${REPO}#quick-start"
    bold ""
}

main "$@"
