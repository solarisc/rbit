//! Per-address admission limits for the SSH listener.
//!
//! An address is counted under the same key the HTTP side uses ([`client_key`]): an IPv6
//! client is counted by its /64, because one host usually owns a whole /64 and would
//! otherwise get an unlimited number of per-address slots. Unauthenticated connections
//! are capped both in total and per address; a connection gives up its unauthenticated
//! slot as soon as it authenticates.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
};

use rbit_services::throttle::client_key;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Connections that have not authenticated yet, across all addresses.
pub(crate) const MAX_UNAUTHENTICATED: usize = 64;
/// Connections that have not authenticated yet, from one address (IPv6: one /64).
pub(crate) const MAX_UNAUTHENTICATED_PER_ADDRESS: usize = 8;

/// Open-connection counts per address key.
#[derive(Debug, Default)]
pub(crate) struct AddressCounts {
    counts: Mutex<HashMap<String, usize>>,
}

impl AddressCounts {
    /// The key `ip` is counted under: canonical (IPv4-mapped addresses as IPv4), with
    /// IPv6 reduced to its /64.
    pub(crate) fn key(ip: IpAddr) -> String {
        client_key(&ip.to_canonical().to_string())
    }

    /// Counts one more connection under `key` when fewer than `limit` are open.
    pub(crate) fn try_take(&self, key: &str, limit: usize) -> bool {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(key.to_owned()).or_default();
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    }

    /// Releases one connection counted under `key`.
    pub(crate) fn release(&self, key: &str) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(key);
            }
        }
    }
}

/// The unauthenticated slot of one connection; released when dropped.
#[derive(Debug)]
pub(crate) struct PreAuthSlot {
    counts: Arc<AddressCounts>,
    key: String,
    _permit: OwnedSemaphorePermit,
}

impl Drop for PreAuthSlot {
    fn drop(&mut self) {
        self.counts.release(&self.key);
    }
}

/// The pre-authentication limits shared by every connection.
#[derive(Debug)]
pub(crate) struct PreAuthLimits {
    total: Arc<Semaphore>,
    per_address: Arc<AddressCounts>,
}

impl PreAuthLimits {
    pub(crate) fn new() -> Self {
        Self { total: Arc::new(Semaphore::new(MAX_UNAUTHENTICATED)), per_address: Arc::new(AddressCounts::default()) }
    }

    /// Takes an unauthenticated slot for a connection from `ip`, or `None` when the total
    /// or the address's share is used up.
    pub(crate) fn admit(&self, ip: IpAddr) -> Option<PreAuthSlot> {
        let key = AddressCounts::key(ip);
        let permit = Arc::clone(&self.total).try_acquire_owned().ok()?;
        if !self.per_address.try_take(&key, MAX_UNAUTHENTICATED_PER_ADDRESS) {
            return None;
        }
        Some(PreAuthSlot { counts: Arc::clone(&self.per_address), key, _permit: permit })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_key() {
        assert_eq!(AddressCounts::key(ip("2001:db8:1:2::1")), AddressCounts::key(ip("2001:db8:1:2:ffff::9")));
        assert_ne!(AddressCounts::key(ip("2001:db8:1:2::1")), AddressCounts::key(ip("2001:db8:1:3::1")));
    }

    #[test]
    fn ipv4_mapped_addresses_count_as_their_ipv4_address() {
        assert_eq!(AddressCounts::key(ip("::ffff:192.0.2.7")), AddressCounts::key(ip("192.0.2.7")));
    }

    #[test]
    fn a_per_address_limit_covers_the_whole_slash_64() {
        let counts = AddressCounts::default();
        let key = AddressCounts::key(ip("2001:db8::1"));
        assert!(counts.try_take(&key, 2));
        // Another host of the same /64 spends the same budget.
        let neighbour = AddressCounts::key(ip("2001:db8::2"));
        assert!(counts.try_take(&neighbour, 2));
        assert!(!counts.try_take(&key, 2));
        counts.release(&key);
        assert!(counts.try_take(&neighbour, 2));
    }

    #[test]
    fn pre_auth_slots_are_capped_per_address_and_released_on_drop() {
        let limits = PreAuthLimits::new();
        let held: Vec<_> = (0..MAX_UNAUTHENTICATED_PER_ADDRESS).map(|_| limits.admit(ip("2001:db8::5")).unwrap()).collect();
        // The ninth unauthenticated connection from the same /64 is refused, from any host in it.
        assert!(limits.admit(ip("2001:db8::6")).is_none());
        // A different /64 is not affected.
        assert!(limits.admit(ip("2001:db9::1")).is_some());
        drop(held);
        assert!(limits.admit(ip("2001:db8::6")).is_some());
    }
}
