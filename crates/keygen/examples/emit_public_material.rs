//! Emit the per-env public-material `{bucket, prefix}` map as JSON.
//!
//! The single source of truth for where each env publishes its public material is
//! `cofhe_keys::reader` (the baked consts). Terraform can't read those consts, so
//! `terraform/service` keeps a hand-authored `local.public_material` mirror to place
//! the write grant and scope the consumer read condition. This emitter lets CI diff
//! the mirror against the truth and fail on drift — see
//! `scripts/check-tf-reader-drift.sh`. It is a tooling helper, never shipped in the
//! keygen image.
use std::collections::BTreeMap;

use cofhe_keys::reader::{env_names, lookup};
use serde_json::json;

fn main() {
    // BTreeMap → keys emitted sorted, so the output is stable regardless of the
    // baked declaration order and lines up with `jq -S` on the Terraform side.
    let mut map = BTreeMap::new();
    for env in env_names() {
        let cfg = lookup(env).expect("baked env from env_names() must resolve");
        map.insert(
            env.to_string(),
            json!({ "bucket": cfg.public_bucket, "prefix": cfg.public_prefix }),
        );
    }
    println!("{}", serde_json::to_string(&map).expect("serialize map"));
}
