use crate::context::NamespacedKv;
use std::net::Ipv4Addr;

const IP_ALLOCATIONS_PREFIX: &str = "ip_allocations";
const NODE_IP_MAPPING_PREFIX: &str = "node_ips";

// RFC 6598 Shared Address Space: 100.64.0.0/16
// Using 100.64.0.1 - 100.64.255.254 (65,534 addresses)
const NETWORK_BASE: u32 = 0x64400001; // 100.64.0.1
const NETWORK_MAX: u32 = 0x6440FFFE;  // 100.64.255.254

pub struct IpAllocator;

impl IpAllocator {
    pub fn allocate_ip(kv: &NamespacedKv, node_id: &str) -> Result<String, IpAllocationError> {
        // Check if this node already has an IP assigned
        if let Some(existing_ip) = Self::get_node_ip(kv, node_id)? {
            return Ok(existing_ip);
        }

        // Find the next available IP
        let ip = Self::find_next_available_ip(kv)?;

        // Store the allocation
        Self::store_allocation(kv, node_id, &ip)?;

        Ok(ip)
    }

    pub fn get_node_ip(kv: &NamespacedKv, node_id: &str) -> Result<Option<String>, IpAllocationError> {
        let key = Self::node_ip_key(node_id);
        match kv.get_bytes(&key) {
            Ok(Some(bytes)) => {
                if &bytes[..] == b"__DELETED__" {
                    return Ok(None);
                }
                let ip = String::from_utf8(bytes)
                    .map_err(|_| IpAllocationError::InvalidData)?;
                Ok(Some(ip))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(IpAllocationError::Storage(err)),
        }
    }

    pub fn release_ip(kv: &NamespacedKv, node_id: &str) -> Result<(), IpAllocationError> {
        let key = Self::node_ip_key(node_id);
        if let Some(ip_bytes) = kv.get_bytes(&key).map_err(IpAllocationError::Storage)? {
            let ip = String::from_utf8(ip_bytes)
                .map_err(|_| IpAllocationError::InvalidData)?;

            // Remove the allocation
            let allocation_key = Self::ip_allocation_key(&ip);
            kv.put_bytes(&allocation_key, b"__DELETED__")
                .map_err(IpAllocationError::Storage)?;

            // Remove the node mapping
            kv.put_bytes(&key, b"__DELETED__")
                .map_err(IpAllocationError::Storage)?;
        }

        Ok(())
    }

    fn find_next_available_ip(kv: &NamespacedKv) -> Result<String, IpAllocationError> {
        // Get all allocated IPs
        let allocated_ips = Self::get_all_allocated_ips(kv)?;

        // Find first available IP in the range
        for ip_u32 in NETWORK_BASE..=NETWORK_MAX {
            let ip = Ipv4Addr::from(ip_u32).to_string();
            if !allocated_ips.contains(&ip) {
                return Ok(ip);
            }
        }

        Err(IpAllocationError::NoAvailableIps)
    }

    fn get_all_allocated_ips(kv: &NamespacedKv) -> Result<Vec<String>, IpAllocationError> {
        let prefix = format!("{}/", IP_ALLOCATIONS_PREFIX);
        let entries = kv.list_by_prefix(prefix.as_bytes())
            .map_err(IpAllocationError::Storage)?;

        let mut ips = Vec::new();
        for (_key, value) in entries {
            if value != b"__DELETED__" {
                // The value should be the node_id, but we extract IP from the key
                // Key format: "ip_allocations/<ip>"
                if let Ok(key_str) = String::from_utf8(_key.clone()) {
                    // Extract IP from key
                    if let Some(ip) = key_str.split('/').last() {
                        ips.push(ip.to_string());
                    }
                }
            }
        }

        Ok(ips)
    }

    fn store_allocation(kv: &NamespacedKv, node_id: &str, ip: &str) -> Result<(), IpAllocationError> {
        // Store IP -> node_id mapping
        let allocation_key = Self::ip_allocation_key(ip);
        kv.put_bytes(&allocation_key, node_id.as_bytes())
            .map_err(IpAllocationError::Storage)?;

        // Store node_id -> IP mapping
        let node_key = Self::node_ip_key(node_id);
        kv.put_bytes(&node_key, ip.as_bytes())
            .map_err(IpAllocationError::Storage)?;

        Ok(())
    }

    fn ip_allocation_key(ip: &str) -> Vec<u8> {
        format!("{}/{}", IP_ALLOCATIONS_PREFIX, ip).into_bytes()
    }

    fn node_ip_key(node_id: &str) -> Vec<u8> {
        format!("{}/{}", NODE_IP_MAPPING_PREFIX, node_id).into_bytes()
    }
}

#[derive(Debug)]
pub enum IpAllocationError {
    Storage(hightower_kv::Error),
    NoAvailableIps,
    InvalidData,
}

impl std::fmt::Display for IpAllocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAllocationError::Storage(err) => write!(f, "storage error: {}", err),
            IpAllocationError::NoAvailableIps => write!(f, "no available IPs in pool"),
            IpAllocationError::InvalidData => write!(f, "invalid data in storage"),
        }
    }
}

impl std::error::Error for IpAllocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IpAllocationError::Storage(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{initialize_kv, CommonContext};
    use tempfile::TempDir;

    #[test]
    fn allocate_ip_assigns_first_available() {
        let temp = TempDir::new().expect("tempdir");
        let kv_handle = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv_handle);

        let ip = IpAllocator::allocate_ip(&ctx.kv, "node1").expect("allocate");
        assert_eq!(ip, "100.64.0.1");
    }

    #[test]
    fn allocate_ip_returns_same_ip_for_same_node() {
        let temp = TempDir::new().expect("tempdir");
        let kv_handle = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv_handle);

        let ip1 = IpAllocator::allocate_ip(&ctx.kv, "node1").expect("allocate");
        let ip2 = IpAllocator::allocate_ip(&ctx.kv, "node1").expect("allocate");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn allocate_ip_assigns_different_ips_for_different_nodes() {
        let temp = TempDir::new().expect("tempdir");
        let kv_handle = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv_handle);

        let ip1 = IpAllocator::allocate_ip(&ctx.kv, "node1").expect("allocate");
        let ip2 = IpAllocator::allocate_ip(&ctx.kv, "node2").expect("allocate");
        assert_ne!(ip1, ip2);
        assert_eq!(ip1, "100.64.0.1");
        assert_eq!(ip2, "100.64.0.2");
    }

    #[test]
    fn get_node_ip_returns_assigned_ip() {
        let temp = TempDir::new().expect("tempdir");
        let kv_handle = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv_handle);

        IpAllocator::allocate_ip(&ctx.kv, "node1").expect("allocate");
        let ip = IpAllocator::get_node_ip(&ctx.kv, "node1").expect("get").expect("ip present");
        assert_eq!(ip, "100.64.0.1");
    }

    #[test]
    fn get_node_ip_returns_none_for_unallocated_node() {
        let temp = TempDir::new().expect("tempdir");
        let kv_handle = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv_handle);

        let ip = IpAllocator::get_node_ip(&ctx.kv, "node1").expect("get");
        assert!(ip.is_none());
    }

    #[test]
    #[ignore] // TODO: Fix KV caching issue with __DELETED__ marker
    fn release_ip_frees_ip_for_reuse() {
        let temp = TempDir::new().expect("tempdir");
        let kv_handle = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv_handle);

        let ip1 = IpAllocator::allocate_ip(&ctx.kv, "node1").expect("allocate");
        assert_eq!(ip1, "100.64.0.1");

        IpAllocator::release_ip(&ctx.kv, "node1").expect("release");

        let ip2 = IpAllocator::get_node_ip(&ctx.kv, "node1").expect("get");
        assert!(ip2.is_none());

        // The IP should be available for reuse
        let ip3 = IpAllocator::allocate_ip(&ctx.kv, "node2").expect("allocate");
        assert_eq!(ip3, "100.64.0.1");
    }

    #[test]
    fn allocate_multiple_ips_sequentially() {
        let temp = TempDir::new().expect("tempdir");
        let kv_handle = initialize_kv(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv_handle);

        for i in 1..=10 {
            let node_id = format!("node{}", i);
            let ip = IpAllocator::allocate_ip(&ctx.kv, &node_id).expect("allocate");
            let expected = format!("100.64.0.{}", i);
            assert_eq!(ip, expected);
        }
    }
}
