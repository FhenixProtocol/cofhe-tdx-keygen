// Public GCS object layout under the baked `{public_prefix}/{public_zone}/`. The three FHE artifacts
// use cofhe's exact mounted file names, so a cofhe stack pointed at this bucket
// reads this ceremony's keyset directly as files
// (keys/versionized/{zone}/{computation_key,public_key,crs}). The manifest sits
// alongside for the consumer reader; the provenance sidecar is still written but
// unread (kept for wire-format compatibility).
#[cfg(not(feature = "mock"))]
pub(crate) const OBJ_SERVER_KEY: &str = "computation_key";
#[cfg(not(feature = "mock"))]
pub(crate) const OBJ_PUBLIC_KEY: &str = "public_key";
#[cfg(not(feature = "mock"))]
pub(crate) const OBJ_CRS: &str = "crs";
#[cfg(not(feature = "mock"))]
pub(crate) const OBJ_MANIFEST: &str = "public-material";

// Object key under the per-zone prefix, e.g. keys/versionized/0/computation_key.
#[cfg(not(feature = "mock"))]
pub(crate) fn object_path(prefix: &str, zone: u32, name: &str) -> String {
    format!("{}/{}/{}", prefix.trim_end_matches('/'), zone, name)
}
