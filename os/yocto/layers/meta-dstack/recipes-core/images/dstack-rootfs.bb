# Unified dstack rootfs image
# Use DSTACK_FLAVOR (via multiconfig) to select variant:
#   prod, dev

# Default flavor settings (can be overridden by multiconfig)
DSTACK_FLAVOR ?= "prod"
DSTACK_DEV ?= "0"

# Base configuration
include dstack-rootfs-base.inc

# Production or development mode
include ${@'dstack-rootfs-dev.inc' if d.getVar('DSTACK_DEV') == '1' else 'dstack-rootfs-prod.inc'}

# NVIDIA support is intentionally omitted for the SNP KMS acceptance image.
# Re-enable this include for the general-purpose GPU image.
# include dstack-rootfs-nvidia.inc
