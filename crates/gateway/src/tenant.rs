//! Shared tenant-domain constants. Kept out of persistence so transport/domain code does not
//! depend on `storage` just to name the default tenant.

pub(crate) const DEFAULT_TENANT_ID: &str = "default";
