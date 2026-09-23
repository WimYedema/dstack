// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! AMD SEV-SNP derived key provider for LUKS disk encryption.
//!
//! This module derives a hardware-based disk unlock key from the SNP processor
//! using VCEK with GUEST_POLICY and MEASUREMENT bindings, then applies HKDF-SHA-256
//! with a fixed dstack-specific context to produce a 32-byte LUKS key.

use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use sha2::Sha256;
use tracing::info;

/// Fixed HKDF context string for dstack AMD KMS LUKS key derivation.
const HKDF_CONTEXT: &[u8] = b"dstack/amd-kms/luks/v1";

/// Guest field select bits for SNP derivation: GUEST_POLICY | MEASUREMENT
fn guest_field_select() -> GuestFieldSelect {
    let mut fields = GuestFieldSelect::default();
    fields.set_guest_policy(true);
    fields.set_measurement(true);
    fields
}

/// Derive a 32-byte LUKS encryption key from SNP hardware.
///
/// Opens `/dev/sev-guest`, requests VCEK with GUEST_POLICY|MEASUREMENT bindings,
/// and applies HKDF-SHA-256 with fixed dstack context to the 32-byte sealing root.
///
/// # Errors
///
/// Returns an error if:
/// - `/dev/sev-guest` is not available (not an SNP guest or unavailable)
/// - SNP firmware is unavailable or does not support `SNP_GET_DERIVED_KEY`
/// - The derivation ioctl fails
///
/// Does not fall back to a generated key; caller must fail-closed if this returns error.
pub fn derive_snp_luks_key() -> Result<[u8; 32]> {
    info!("Attempting to derive SNP-based LUKS key from hardware");

    // Open /dev/sev-guest for SNP ioctl
    let mut firmware = Firmware::open()
        .context("Failed to open /dev/sev-guest: SNP guest device unavailable or permission denied")?;

    // Prepare SNP_GET_DERIVED_KEY request with VCEK root (root_key_select=false),
    // GUEST_POLICY|MEASUREMENT fields, VMPL 0, guest SVN 0, TCB version 0
    let fields = guest_field_select();
    let request = DerivedKey::new(
        false, /* root_key_select: use VCEK, not VMRK */
        fields,
        0, /* vmpl */
        0, /* guest_svn */
        0, /* tcb_version */
    );

    // Issue the derivation request
    let sealing_root = firmware
        .get_derived_key(None, request)
        .context("SNP_GET_DERIVED_KEY ioctl failed: firmware may be unavailable or request fields unsupported")?;

    // Apply HKDF-SHA-256 with fixed dstack context to produce final LUKS key
    let hk = Hkdf::<Sha256>::new(None, &sealing_root);
    let mut luks_key = [0u8; 32];
    hk.expand(HKDF_CONTEXT, &mut luks_key)
        .map_err(|e| anyhow!("HKDF-SHA-256 expansion failed: {}", e))?;

    info!("Successfully derived SNP LUKS key");
    Ok(luks_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha256_is_deterministic() {
        // Fixed test vector: sealing root that we'll apply HKDF to
        let sealing_root = [0x42u8; 32];

        // Apply HKDF twice with same inputs
        let hk1 = Hkdf::<Sha256>::new(None, &sealing_root);
        let mut luks_key1 = [0u8; 32];
        hk1.expand(HKDF_CONTEXT, &mut luks_key1)
            .map_err(|e| format!("HKDF expand failed: {}", e))
            .unwrap();

        let hk2 = Hkdf::<Sha256>::new(None, &sealing_root);
        let mut luks_key2 = [0u8; 32];
        hk2.expand(HKDF_CONTEXT, &mut luks_key2)
            .map_err(|e| format!("HKDF expand failed: {}", e))
            .unwrap();

        assert_eq!(
            luks_key1, luks_key2,
            "HKDF-SHA-256 must produce same key for same inputs"
        );
    }

    #[test]
    fn hkdf_changes_with_different_sealing_root() {
        let sealing_root_1 = [0x11u8; 32];
        let sealing_root_2 = [0x22u8; 32];

        let hk1 = Hkdf::<Sha256>::new(None, &sealing_root_1);
        let mut luks_key1 = [0u8; 32];
        hk1.expand(HKDF_CONTEXT, &mut luks_key1)
            .map_err(|e| format!("HKDF expand failed: {}", e))
            .unwrap();

        let hk2 = Hkdf::<Sha256>::new(None, &sealing_root_2);
        let mut luks_key2 = [0u8; 32];
        hk2.expand(HKDF_CONTEXT, &mut luks_key2)
            .map_err(|e| format!("HKDF expand failed: {}", e))
            .unwrap();

        assert_ne!(
            luks_key1, luks_key2,
            "HKDF-SHA-256 must produce different keys for different sealing roots"
        );
    }

    #[test]
    fn hkdf_context_affects_key() {
        let sealing_root = [0x42u8; 32];

        let hk1 = Hkdf::<Sha256>::new(None, &sealing_root);
        let mut luks_key1 = [0u8; 32];
        hk1.expand(HKDF_CONTEXT, &mut luks_key1)
            .map_err(|e| format!("HKDF expand failed: {}", e))
            .unwrap();

        let hk2 = Hkdf::<Sha256>::new(None, &sealing_root);
        let mut luks_key2 = [0u8; 32];
        hk2.expand(b"different/context", &mut luks_key2)
            .map_err(|e| format!("HKDF expand failed: {}", e))
            .unwrap();

        assert_ne!(
            luks_key1, luks_key2,
            "HKDF-SHA-256 must produce different keys for different contexts"
        );
    }

    #[test]
    fn guest_field_select_has_policy_and_measurement() {
        let fields = guest_field_select();
        // Verify GUEST_POLICY and MEASUREMENT are selected
        assert!(fields.get_guest_policy());
        assert!(fields.get_measurement());
    }
}

