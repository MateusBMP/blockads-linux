# Which tests/vm/platform_checks.sh sections run on which distribution.
# Sourced by tests/vm/run_platform.sh (qemu VMs) and tests/ci/system.sh (a GitHub
# runner used directly as the machine under test).
PLATFORM_COMMON="interception unit sni sandbox freebind nm polkit pinned nftflush"
platform_sections() {  # platform_sections IMAGE
    case $1 in
        debian12|debian13|arch) echo "$PLATFORM_COMMON docker" ;;
        ubuntu2404|ubuntu2604) echo "$PLATFORM_COMMON ufw" ;;
        fedora44) echo "$PLATFORM_COMMON firewalld" ;;
        *) echo "platform_sections: unknown image $1" >&2; return 1 ;;
    esac
}
