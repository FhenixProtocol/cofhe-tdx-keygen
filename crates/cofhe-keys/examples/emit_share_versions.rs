//! Prints `<env> <share_version>`, one line per baked env, for the CI check
//! `scripts/check-share-version-never-down.sh`.

fn main() -> anyhow::Result<()> {
    for name in cofhe_keys::envs::env_names() {
        println!("{name} {}", cofhe_keys::envs::lookup(name)?.share_version);
    }
    Ok(())
}
