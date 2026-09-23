IMAGE_INSTALL += "packagegroup-core-ssh-openssh strace tcpdump gdb gdbserver vim dstack-tee-simulator coreutils"
EXTRA_IMAGE_FEATURES += "allow-root-login post-install-logging"

# Debug-only: seed root's authorized_keys for interactive SSH troubleshooting.
# Remove before this becomes a non-debug change.
debug_install_ssh_key() {
    install -m 0700 -d ${IMAGE_ROOTFS}/root/.ssh
    install -m 0600 /home/ubuntu/wimyedema/spikes/offline-local-kms/debug-kms-ssh-key.pub \
        ${IMAGE_ROOTFS}/root/.ssh/authorized_keys
}
ROOTFS_POSTPROCESS_COMMAND += "debug_install_ssh_key; "

DOCKER_DAEMON_JSON = "${THISDIR}/files/docker-daemon-dev.json"