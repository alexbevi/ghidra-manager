#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANAGED_DIR="$ROOT_DIR/.managed"
GHIDRA_COMPONENTS_DIR="$MANAGED_DIR/ghidra"
MCP_COMPONENTS_DIR="$MANAGED_DIR/ghidra-mcp"
PAIRS_DIR="$MANAGED_DIR/pairs"
CURRENT_LINK="$MANAGED_DIR/current"
PREVIOUS_LINK="$MANAGED_DIR/previous"
TEMP_DIR=""

GHIDRA_REPOSITORY="NationalSecurityAgency/ghidra"
MCP_REPOSITORY="bethington/ghidra-mcp"
GITHUB_API="https://api.github.com"

MCP_TAG=""
MCP_VERSION=""
MCP_GHIDRA_VERSION=""
MCP_EXTENSION_NAME=""
MCP_EXTENSION_URL=""
MCP_EXTENSION_DIGEST=""
MCP_BRIDGE_NAME=""
MCP_BRIDGE_URL=""
MCP_BRIDGE_DIGEST=""
MCP_REQUIREMENTS_NAME=""
MCP_REQUIREMENTS_URL=""
MCP_REQUIREMENTS_DIGEST=""
GHIDRA_TAG=""
GHIDRA_VERSION=""
GHIDRA_LATEST_VERSION=""
GHIDRA_ASSET_NAME=""
GHIDRA_ASSET_URL=""
GHIDRA_ASSET_DIGEST=""
RESOLVED_EXTENSION_PATH=""
EXTENSION_TRANSACTION_ACTIVE=false
EXTENSION_TRANSACTION_TARGET=""
EXTENSION_TRANSACTION_BACKUP=""

log() {
    printf '%s\n' "$*"
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [ "$EXTENSION_TRANSACTION_ACTIVE" = true ] && [ -n "$EXTENSION_TRANSACTION_TARGET" ]; then
        rm -rf "$EXTENSION_TRANSACTION_TARGET"
        if [ -n "$EXTENSION_TRANSACTION_BACKUP" ] && [ -d "$EXTENSION_TRANSACTION_BACKUP" ]; then
            mv "$EXTENSION_TRANSACTION_BACKUP" "$EXTENSION_TRANSACTION_TARGET"
        fi
        EXTENSION_TRANSACTION_ACTIVE=false
    fi
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    cat <<'EOF'
Usage: ./ghidra-manager.sh [command]

Commands:
  sync [--dry-run]  Install or update the newest compatible stable pair (default)
  status            Show installed and upstream versions
  launch [args...]  Launch the active Ghidra with JDK 21
  bridge [args...]  Run the active GhidraMCP bridge with managed Python 3.13
  rollback          Swap to the previously active compatible pair
  help              Show this help

Environment:
  GH_TOKEN           Optional GitHub API token
  GITHUB_TOKEN       Optional GitHub API token (used when GH_TOKEN is unset)
EOF
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

preflight() {
    require_command curl
    require_command jq
    require_command shasum
    require_command unzip
}

make_temp_dir() {
    [ -z "$TEMP_DIR" ] || return 0
    TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ghidra-manager.XXXXXX")
}

github_headers() {
    printf '%s\n' "Accept: application/vnd.github+json"
    printf '%s\n' "X-GitHub-Api-Version: 2022-11-28"
    printf '%s\n' "User-Agent: local-ghidra-manager"
}

api_get() {
    local endpoint=$1
    local token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
    local headers=()
    local header

    while IFS= read -r header; do
        headers+=( -H "$header" )
    done < <(github_headers)
    if [ -n "$token" ]; then
        headers+=( -H "Authorization: Bearer $token" )
    fi

    curl --fail --location --silent --show-error "${headers[@]}" \
        "$GITHUB_API/$endpoint"
}

download_file() {
    local url=$1
    local destination=$2
    local token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
    local args=(--fail --location --silent --show-error)

    if [ -n "$token" ]; then
        args+=( -H "Authorization: Bearer $token" )
    fi
    curl "${args[@]}" --output "$destination" "$url"
}

sha256_from_digest() {
    local digest=$1
    case "$digest" in
        sha256:[0-9a-fA-F][0-9a-fA-F]*) printf '%s\n' "${digest#sha256:}" ;;
        *) die "Release asset has no usable SHA-256 digest" ;;
    esac
}

verify_digest() {
    local path=$1
    local digest=$2
    local expected
    local actual

    expected=$(sha256_from_digest "$digest")
    [ ${#expected} -eq 64 ] || die "Invalid SHA-256 digest for $(basename "$path")"
    actual=$(shasum -a 256 "$path" | awk '{print $1}')
    [ "$actual" = "$expected" ] || die "SHA-256 mismatch for $(basename "$path")"
}

asset_field() {
    local release_json=$1
    local selector=$2
    local field=$3

    jq -er --arg selector "$selector" --arg field "$field" '
        [.assets[] | select(.name | test($selector))]
        | if length == 1 then .[0][$field] else error("expected one matching release asset") end
    ' "$release_json"
}

extension_property() {
    local archive=$1
    local property=$2
    unzip -p "$archive" 'GhidraMCP/extension.properties' \
        | awk -F= -v key="$property" '$1 == key {sub(/^[^=]*=/, ""); print; exit}'
}

extension_plugin_version() {
    local archive=$1
    extension_property "$archive" description \
        | sed -n 's/.*Plugin version \([0-9][0-9.]*\)\..*/\1/p'
}

resolve_remote_pair() {
    local mcp_release_json
    local ghidra_release_json
    local ghidra_latest_json

    make_temp_dir
    mcp_release_json="$TEMP_DIR/mcp-release.json"
    ghidra_release_json="$TEMP_DIR/ghidra-release.json"
    ghidra_latest_json="$TEMP_DIR/ghidra-latest.json"

    api_get "repos/$MCP_REPOSITORY/releases/latest" > "$mcp_release_json"
    MCP_TAG=$(jq -er '.tag_name' "$mcp_release_json")
    MCP_VERSION=${MCP_TAG#v}

    MCP_EXTENSION_NAME=$(asset_field "$mcp_release_json" '^GhidraMCP-[0-9].*\.zip$' name)
    MCP_EXTENSION_URL=$(asset_field "$mcp_release_json" '^GhidraMCP-[0-9].*\.zip$' browser_download_url)
    MCP_EXTENSION_DIGEST=$(asset_field "$mcp_release_json" '^GhidraMCP-[0-9].*\.zip$' digest)
    MCP_BRIDGE_NAME=$(asset_field "$mcp_release_json" '^bridge_mcp_ghidra\.py$' name)
    MCP_BRIDGE_URL=$(asset_field "$mcp_release_json" '^bridge_mcp_ghidra\.py$' browser_download_url)
    MCP_BRIDGE_DIGEST=$(asset_field "$mcp_release_json" '^bridge_mcp_ghidra\.py$' digest)
    MCP_REQUIREMENTS_NAME=$(asset_field "$mcp_release_json" '^requirements\.txt$' name)
    MCP_REQUIREMENTS_URL=$(asset_field "$mcp_release_json" '^requirements\.txt$' browser_download_url)
    MCP_REQUIREMENTS_DIGEST=$(asset_field "$mcp_release_json" '^requirements\.txt$' digest)

    RESOLVED_EXTENSION_PATH="$TEMP_DIR/$MCP_EXTENSION_NAME"
    download_file "$MCP_EXTENSION_URL" "$RESOLVED_EXTENSION_PATH"
    verify_digest "$RESOLVED_EXTENSION_PATH" "$MCP_EXTENSION_DIGEST"

    [ "$(extension_property "$RESOLVED_EXTENSION_PATH" name)" = "GhidraMCP" ] \
        || die "Unexpected extension name in $MCP_EXTENSION_NAME"
    [ "$(extension_plugin_version "$RESOLVED_EXTENSION_PATH")" = "$MCP_VERSION" ] \
        || die "MCP release tag and extension metadata do not match"
    MCP_GHIDRA_VERSION=$(extension_property "$RESOLVED_EXTENSION_PATH" version)
    [ -n "$MCP_GHIDRA_VERSION" ] || die "GhidraMCP extension declares no Ghidra version"

    GHIDRA_TAG="Ghidra_${MCP_GHIDRA_VERSION}_build"
    api_get "repos/$GHIDRA_REPOSITORY/releases/tags/$GHIDRA_TAG" > "$ghidra_release_json"
    GHIDRA_VERSION=$MCP_GHIDRA_VERSION
    GHIDRA_ASSET_NAME=$(asset_field "$ghidra_release_json" "^ghidra_${GHIDRA_VERSION//./\\.}_PUBLIC_[0-9]+\\.zip$" name)
    GHIDRA_ASSET_URL=$(asset_field "$ghidra_release_json" "^ghidra_${GHIDRA_VERSION//./\\.}_PUBLIC_[0-9]+\\.zip$" browser_download_url)
    GHIDRA_ASSET_DIGEST=$(asset_field "$ghidra_release_json" "^ghidra_${GHIDRA_VERSION//./\\.}_PUBLIC_[0-9]+\\.zip$" digest)

    api_get "repos/$GHIDRA_REPOSITORY/releases/latest" > "$ghidra_latest_json"
    GHIDRA_LATEST_VERSION=$(jq -er '.name | sub("^Ghidra "; "")' "$ghidra_latest_json")
}

pair_name() {
    printf 'ghidra-%s__mcp-%s\n' "$1" "$2"
}

pair_value() {
    local pair_path=$1
    local key=$2
    local metadata="$pair_path/metadata"

    [ -f "$metadata" ] || return 1
    awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$metadata"
}

current_value() {
    [ -L "$CURRENT_LINK" ] || return 1
    pair_value "$CURRENT_LINK" "$1"
}

validate_ghidra_install() {
    local install_dir=$1
    local expected_version=$2
    local actual_version

    [ -x "$install_dir/ghidraRun" ] || return 1
    [ -f "$install_dir/Ghidra/application.properties" ] || return 1
    actual_version=$(awk -F= '$1 == "application.version" {print $2; exit}' \
        "$install_dir/Ghidra/application.properties")
    [ "$actual_version" = "$expected_version" ]
}

require_active_pair() {
    [ -L "$CURRENT_LINK" ] && [ -d "$CURRENT_LINK" ] \
        || die "No active pair. Run ./ghidra-manager.sh sync first."
}

stage_mcp_component() {
    local destination="$MCP_COMPONENTS_DIR/$MCP_VERSION"
    local stage="$TEMP_DIR/mcp-component"

    if [ -f "$destination/$MCP_EXTENSION_NAME" ] \
        && [ -f "$destination/$MCP_BRIDGE_NAME" ] \
        && [ -f "$destination/$MCP_REQUIREMENTS_NAME" ]; then
        return 0
    fi

    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$RESOLVED_EXTENSION_PATH" "$stage/$MCP_EXTENSION_NAME"
    download_file "$MCP_BRIDGE_URL" "$stage/$MCP_BRIDGE_NAME"
    download_file "$MCP_REQUIREMENTS_URL" "$stage/$MCP_REQUIREMENTS_NAME"
    verify_digest "$stage/$MCP_BRIDGE_NAME" "$MCP_BRIDGE_DIGEST"
    verify_digest "$stage/$MCP_REQUIREMENTS_NAME" "$MCP_REQUIREMENTS_DIGEST"
    cat > "$stage/metadata" <<EOF
mcp_version=$MCP_VERSION
mcp_tag=$MCP_TAG
ghidra_version=$GHIDRA_VERSION
extension_asset=$MCP_EXTENSION_NAME
bridge_asset=$MCP_BRIDGE_NAME
requirements_asset=$MCP_REQUIREMENTS_NAME
EOF
    mkdir -p "$MCP_COMPONENTS_DIR"
    rm -rf "$destination"
    mv "$stage" "$destination"
}

stage_ghidra_component() {
    local destination="$GHIDRA_COMPONENTS_DIR/$GHIDRA_VERSION"
    local archive="$TEMP_DIR/$GHIDRA_ASSET_NAME"
    local extract_dir="$TEMP_DIR/ghidra-extract"
    local extracted_root

    if validate_ghidra_install "$destination" "$GHIDRA_VERSION"; then
        return 0
    fi

    log "Downloading Ghidra $GHIDRA_VERSION..."
    download_file "$GHIDRA_ASSET_URL" "$archive"
    verify_digest "$archive" "$GHIDRA_ASSET_DIGEST"
    mkdir -p "$extract_dir"
    unzip -q "$archive" -d "$extract_dir"
    extracted_root=$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    [ -n "$extracted_root" ] || die "Ghidra archive did not contain an installation directory"
    validate_ghidra_install "$extracted_root" "$GHIDRA_VERSION" \
        || die "Extracted Ghidra installation failed validation"
    cat > "$extracted_root/.manager-metadata" <<EOF
ghidra_version=$GHIDRA_VERSION
ghidra_tag=$GHIDRA_TAG
asset=$GHIDRA_ASSET_NAME
digest=$GHIDRA_ASSET_DIGEST
EOF
    mkdir -p "$GHIDRA_COMPONENTS_DIR"
    rm -rf "$destination"
    mv "$extracted_root" "$destination"
}

managed_ghidra_running() {
    ps -axo command= | grep -F "$GHIDRA_COMPONENTS_DIR/" | grep -E 'ghidra\.Ghidra|ghidraRun' >/dev/null 2>&1
}

installed_mcp_version() {
    local install_dir=$1
    local properties="$install_dir/Ghidra/Extensions/GhidraMCP/extension.properties"
    [ -f "$properties" ] || return 1
    sed -n 's/.*Plugin version \([0-9][0-9.]*\)\..*/\1/p' "$properties"
}

install_mcp_extension() {
    local ghidra_dir="$GHIDRA_COMPONENTS_DIR/$GHIDRA_VERSION"
    local archive="$MCP_COMPONENTS_DIR/$MCP_VERSION/$MCP_EXTENSION_NAME"
    local extensions_dir="$ghidra_dir/Ghidra/Extensions"
    local target="$extensions_dir/GhidraMCP"
    local unpacked="$TEMP_DIR/extension-unpacked"
    local backup="$TEMP_DIR/extension-backup"

    if [ "$(installed_mcp_version "$ghidra_dir" 2>/dev/null || true)" = "$MCP_VERSION" ]; then
        return 0
    fi
    managed_ghidra_running && die "Close the managed Ghidra instance before updating its extension"

    rm -rf "$unpacked" "$backup"
    mkdir -p "$unpacked" "$extensions_dir"
    unzip -q "$archive" -d "$unpacked"
    [ "$(extension_property "$archive" version)" = "$GHIDRA_VERSION" ] \
        || die "Extension is incompatible with the staged Ghidra installation"
    [ -d "$unpacked/GhidraMCP" ] || die "Extension archive has an unexpected layout"

    if [ -d "$target" ]; then
        mv "$target" "$backup"
    fi
    EXTENSION_TRANSACTION_ACTIVE=true
    EXTENSION_TRANSACTION_TARGET="$target"
    EXTENSION_TRANSACTION_BACKUP="$backup"
    if ! mv "$unpacked/GhidraMCP" "$target"; then
        die "Failed to install GhidraMCP extension"
    fi
}

commit_extension_install() {
    if [ "$EXTENSION_TRANSACTION_ACTIVE" = true ]; then
        rm -rf "$EXTENSION_TRANSACTION_BACKUP"
    fi
    EXTENSION_TRANSACTION_ACTIVE=false
    EXTENSION_TRANSACTION_TARGET=""
    EXTENSION_TRANSACTION_BACKUP=""
}

activate_pair() {
    local name
    local pair_path
    local pair_stage
    local old_current=""

    name=$(pair_name "$GHIDRA_VERSION" "$MCP_VERSION")
    pair_path="$PAIRS_DIR/$name"
    pair_stage="$TEMP_DIR/$name"
    mkdir -p "$pair_stage" "$PAIRS_DIR"
    ln -s "$GHIDRA_COMPONENTS_DIR/$GHIDRA_VERSION" "$pair_stage/ghidra"
    ln -s "$MCP_COMPONENTS_DIR/$MCP_VERSION" "$pair_stage/ghidra-mcp"
    cat > "$pair_stage/metadata" <<EOF
ghidra_version=$GHIDRA_VERSION
mcp_version=$MCP_VERSION
ghidra_tag=$GHIDRA_TAG
mcp_tag=$MCP_TAG
EOF
    if [ -d "$pair_path" ]; then
        rm -rf "$pair_stage"
    else
        mv "$pair_stage" "$pair_path"
    fi
    if [ -L "$CURRENT_LINK" ]; then
        old_current=$(readlink "$CURRENT_LINK")
    fi
    if [ -n "$old_current" ] && [ "$old_current" != "$pair_path" ] && [ -d "$old_current" ]; then
        replace_link "$PREVIOUS_LINK" "$old_current"
    fi
    replace_link "$CURRENT_LINK" "$pair_path"
}

replace_link() {
    local link_path=$1
    local target=$2
    local staged_link="${link_path}.next.$$"

    mkdir -p "$(dirname "$link_path")"
    rm -f "$staged_link"
    ln -s "$target" "$staged_link"
    mv -fh "$staged_link" "$link_path"
}

prune_retained_components() {
    local keep_ghidra=""
    local keep_previous_ghidra=""
    local keep_mcp=""
    local keep_previous_mcp=""
    local current_pair=""
    local previous_pair=""
    local path
    local name

    if [ -L "$CURRENT_LINK" ] && [ -d "$CURRENT_LINK" ]; then
        keep_ghidra=$(pair_value "$CURRENT_LINK" ghidra_version 2>/dev/null || true)
        keep_mcp=$(pair_value "$CURRENT_LINK" mcp_version 2>/dev/null || true)
        current_pair=$(readlink "$CURRENT_LINK")
    fi
    if [ -L "$PREVIOUS_LINK" ] && [ -d "$PREVIOUS_LINK" ]; then
        keep_previous_ghidra=$(pair_value "$PREVIOUS_LINK" ghidra_version 2>/dev/null || true)
        keep_previous_mcp=$(pair_value "$PREVIOUS_LINK" mcp_version 2>/dev/null || true)
        previous_pair=$(readlink "$PREVIOUS_LINK")
    fi

    for path in "$GHIDRA_COMPONENTS_DIR"/*; do
        [ -d "$path" ] || continue
        name=$(basename "$path")
        if [ "$name" != "$keep_ghidra" ] && [ "$name" != "$keep_previous_ghidra" ]; then
            rm -rf "$path"
        fi
    done
    for path in "$MCP_COMPONENTS_DIR"/*; do
        [ -d "$path" ] || continue
        name=$(basename "$path")
        if [ "$name" != "$keep_mcp" ] && [ "$name" != "$keep_previous_mcp" ]; then
            rm -rf "$path"
        fi
    done
    for path in "$PAIRS_DIR"/*; do
        [ -d "$path" ] || continue
        if [ "$path" != "$current_pair" ] && [ "$path" != "$previous_pair" ]; then
            rm -rf "$path"
        fi
    done
}

java_major_version() {
    local java_home=$1
    "$java_home/bin/java" -version 2>&1 \
        | awk -F'[".]' '/version/ {print $2; exit}'
}

find_java21() {
    local candidate=""

    if [ -x /usr/libexec/java_home ]; then
        candidate=$(/usr/libexec/java_home -v 21 2>/dev/null || true)
        if [ -n "$candidate" ] && [ "$(java_major_version "$candidate")" = "21" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    if command -v brew >/dev/null 2>&1; then
        candidate=$(brew --prefix openjdk@21 2>/dev/null || true)
        if [ -n "$candidate" ] && [ "$(java_major_version "$candidate")" = "21" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ] \
        && [ "$(java_major_version "$JAVA_HOME")" = "21" ]; then
        printf '%s\n' "$JAVA_HOME"
        return 0
    fi
    return 1
}

print_remote_summary() {
    log "Upstream Ghidra:    $GHIDRA_LATEST_VERSION"
    log "Compatible Ghidra:  $GHIDRA_VERSION"
    log "Upstream GhidraMCP: $MCP_VERSION"
    if [ "$GHIDRA_LATEST_VERSION" != "$GHIDRA_VERSION" ]; then
        log "Update held: GhidraMCP $MCP_VERSION declares Ghidra $GHIDRA_VERSION."
    fi
}

command_sync() {
    local dry_run=false
    local current_ghidra
    local current_mcp

    if [ "${1:-}" = "--dry-run" ]; then
        dry_run=true
        shift
    fi
    [ $# -eq 0 ] || die "sync accepts only --dry-run"

    preflight
    log "Resolving stable upstream releases..."
    resolve_remote_pair
    print_remote_summary
    current_ghidra=$(current_value ghidra_version 2>/dev/null || true)
    current_mcp=$(current_value mcp_version 2>/dev/null || true)

    if [ "$dry_run" = true ]; then
        if [ "$current_ghidra" = "$GHIDRA_VERSION" ] && [ "$current_mcp" = "$MCP_VERSION" ]; then
            log "Dry run: the active pair is already current."
        else
            log "Dry run: would activate Ghidra $GHIDRA_VERSION with GhidraMCP $MCP_VERSION."
        fi
        return 0
    fi

    if [ "$current_ghidra" = "$GHIDRA_VERSION" ] \
        && [ "$current_mcp" = "$MCP_VERSION" ] \
        && validate_ghidra_install "$GHIDRA_COMPONENTS_DIR/$GHIDRA_VERSION" "$GHIDRA_VERSION" \
        && [ -f "$MCP_COMPONENTS_DIR/$MCP_VERSION/$MCP_EXTENSION_NAME" ] \
        && [ -f "$MCP_COMPONENTS_DIR/$MCP_VERSION/$MCP_BRIDGE_NAME" ] \
        && [ -f "$MCP_COMPONENTS_DIR/$MCP_VERSION/$MCP_REQUIREMENTS_NAME" ] \
        && [ "$(installed_mcp_version "$GHIDRA_COMPONENTS_DIR/$GHIDRA_VERSION" 2>/dev/null || true)" = "$MCP_VERSION" ]; then
        log "Already current: Ghidra $GHIDRA_VERSION with GhidraMCP $MCP_VERSION."
        return 0
    fi

    managed_ghidra_running && die "Close the managed Ghidra instance before syncing"
    stage_mcp_component
    stage_ghidra_component
    install_mcp_extension
    activate_pair
    commit_extension_install
    prune_retained_components
    log "Active pair: Ghidra $GHIDRA_VERSION with GhidraMCP $MCP_VERSION."
}

command_status() {
    local current_ghidra
    local current_mcp
    local installed_mcp=""
    local previous_ghidra
    local previous_mcp

    current_ghidra=$(current_value ghidra_version 2>/dev/null || true)
    current_mcp=$(current_value mcp_version 2>/dev/null || true)
    if [ -n "$current_ghidra" ]; then
        installed_mcp=$(installed_mcp_version "$GHIDRA_COMPONENTS_DIR/$current_ghidra" 2>/dev/null || true)
        log "Active Ghidra:      $current_ghidra"
        log "Active GhidraMCP:   $current_mcp"
        log "Installed extension: ${installed_mcp:-missing}"
    else
        log "Active pair:        not installed"
    fi
    previous_ghidra=$(pair_value "$PREVIOUS_LINK" ghidra_version 2>/dev/null || true)
    previous_mcp=$(pair_value "$PREVIOUS_LINK" mcp_version 2>/dev/null || true)
    if [ -n "$previous_ghidra" ]; then
        log "Previous pair:      Ghidra $previous_ghidra with GhidraMCP $previous_mcp"
    else
        log "Previous pair:      none"
    fi

    preflight
    resolve_remote_pair
    print_remote_summary
}

command_launch() {
    local java_home
    local launcher

    require_active_pair
    java_home=$(find_java21) \
        || die "JDK 21 not found. Install it with: brew install openjdk@21"
    launcher="$CURRENT_LINK/ghidra/ghidraRun"
    [ -x "$launcher" ] || die "Active Ghidra launcher is missing. Run sync to repair it."
    log "Launching Ghidra $(pair_value "$CURRENT_LINK" ghidra_version) with JDK 21..."
    exec env JAVA_HOME="$java_home" PATH="$java_home/bin:$PATH" "$launcher" "$@"
}

command_bridge() {
    local bridge_asset
    local bridge_path

    require_active_pair
    require_command uv
    bridge_asset=$(pair_value "$CURRENT_LINK/ghidra-mcp" bridge_asset)
    [ -n "$bridge_asset" ] || die "Active MCP component has no bridge asset metadata"
    bridge_path="$CURRENT_LINK/ghidra-mcp/$bridge_asset"
    [ -f "$bridge_path" ] || die "Active MCP bridge is missing. Run sync to repair it."
    mkdir -p "$MANAGED_DIR/python" "$MANAGED_DIR/uv-cache"
    exec env \
        UV_PYTHON_INSTALL_DIR="$MANAGED_DIR/python" \
        UV_CACHE_DIR="$MANAGED_DIR/uv-cache" \
        uv run --python 3.13 --managed-python --no-project --script "$bridge_path" "$@"
}

command_rollback() {
    local old_current
    local rollback_target

    [ -L "$PREVIOUS_LINK" ] && [ -d "$PREVIOUS_LINK" ] \
        || die "No previous pair is available for rollback"
    require_active_pair
    managed_ghidra_running && die "Close the managed Ghidra instance before rolling back"
    preflight
    make_temp_dir

    old_current=$(readlink "$CURRENT_LINK")
    rollback_target=$(readlink "$PREVIOUS_LINK")
    GHIDRA_VERSION=$(pair_value "$PREVIOUS_LINK" ghidra_version)
    MCP_VERSION=$(pair_value "$PREVIOUS_LINK" mcp_version)
    MCP_EXTENSION_NAME=$(pair_value "$PREVIOUS_LINK/ghidra-mcp" extension_asset)
    [ -n "$GHIDRA_VERSION" ] && [ -n "$MCP_VERSION" ] && [ -n "$MCP_EXTENSION_NAME" ] \
        || die "Previous pair metadata is incomplete"
    validate_ghidra_install "$GHIDRA_COMPONENTS_DIR/$GHIDRA_VERSION" "$GHIDRA_VERSION" \
        || die "Previous Ghidra installation is missing or invalid"
    [ -f "$MCP_COMPONENTS_DIR/$MCP_VERSION/$MCP_EXTENSION_NAME" ] \
        || die "Previous GhidraMCP extension archive is missing"

    install_mcp_extension
    replace_link "$CURRENT_LINK" "$rollback_target"
    replace_link "$PREVIOUS_LINK" "$old_current"
    commit_extension_install
    prune_retained_components
    log "Rolled back to Ghidra $GHIDRA_VERSION with GhidraMCP $MCP_VERSION."
}

main() {
    local command=${1:-sync}
    if [ $# -gt 0 ]; then
        shift
    fi

    case "$command" in
        sync) command_sync "$@" ;;
        status) [ $# -eq 0 ] || die "status accepts no arguments"; command_status ;;
        launch) command_launch "$@" ;;
        bridge) command_bridge "$@" ;;
        rollback) [ $# -eq 0 ] || die "rollback accepts no arguments"; command_rollback ;;
        help|-h|--help) usage ;;
        *) usage >&2; die "Unknown command: $command" ;;
    esac
}

main "$@"
