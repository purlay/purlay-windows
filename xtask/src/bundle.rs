//! Fetching, pinning and verifying the server's contract bundle (server D-186, D-192).

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Lock {
    pub bundle_format: u64,
    pub contract_version: u64,
    pub manifest_sha256: String,
    pub server_version: String,
}

impl Lock {
    pub fn read(root: &Path) -> Result<Lock> {
        let v = crate::read_json(&root.join("Contract/contract.lock"))?;
        Ok(Lock {
            bundle_format: v["bundleFormat"].as_u64().context("bundleFormat")?,
            contract_version: v["contractVersion"].as_u64().context("contractVersion")?,
            manifest_sha256: v["manifestSha256"].as_str().context("manifestSha256")?.to_string(),
            server_version: v["serverVersion"].as_str().context("serverVersion")?.to_string(),
        })
    }

    fn write(&self, root: &Path) -> Result<()> {
        let body = format!(
            "{{\n  \"bundleFormat\": {},\n  \"contractVersion\": {},\n  \"manifestSha256\": \"{}\",\n  \"serverVersion\": \"{}\"\n}}\n",
            self.bundle_format, self.contract_version, self.manifest_sha256, self.server_version
        );
        let contract = root.join("Contract");
        let mut staged = tempfile::NamedTempFile::new_in(&contract)?;
        staged.write_all(body.as_bytes())?;
        staged.persist(contract.join("contract.lock"))?;
        Ok(())
    }
}

pub fn bundle_dir(root: &Path, server_version: &str) -> PathBuf {
    root.join("Contract/bundle").join(format!("purlay-contract-v{server_version}"))
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Checks every file against `MANIFEST.json`, refuses extra files, and checks the
/// manifest's own digest against `Contract/contract.lock`. Returns the bundle directory.
pub fn verify(root: &Path) -> Result<PathBuf> {
    let lock = Lock::read(root)?;
    let dir = bundle_dir(root, &lock.server_version);
    if !dir.exists() {
        bail!(
            "bundle {} is missing; run `cargo xtask contract fetch`",
            dir.display()
        );
    }
    verify_bundle(&dir, &lock)?;
    Ok(dir)
}

fn verify_bundle(dir: &Path, lock: &Lock) -> Result<()> {
    let manifest_path = dir.join("MANIFEST.json");
    let digest = sha256_file(&manifest_path)?;
    if digest != lock.manifest_sha256 {
        bail!("MANIFEST.json digest {digest} does not match the lock {}", lock.manifest_sha256);
    }
    let manifest = crate::read_json(&manifest_path)?;
    if manifest["format"].as_u64() != Some(lock.bundle_format) {
        bail!("bundle format differs from the lock");
    }
    if manifest["contractVersion"].as_u64() != Some(lock.contract_version) {
        bail!("contract version differs from the lock");
    }
    if manifest["serverVersion"].as_str() != Some(lock.server_version.as_str()) {
        bail!("server version differs from the lock");
    }
    let mut listed = std::collections::BTreeSet::new();
    for f in manifest["files"].as_array().context("files")? {
        let rel = f["path"].as_str().context("path")?;
        let want = f["sha256"].as_str().context("sha256")?;
        let got = sha256_file(&dir.join(rel))?;
        if got != want {
            bail!("{rel}: digest {got} differs from the manifest's {want}");
        }
        listed.insert(rel.replace('\\', "/"));
    }
    listed.insert("MANIFEST.json".into());
    for entry in walk(dir)? {
        let rel = entry.strip_prefix(dir)?.to_string_lossy().replace('\\', "/");
        if !listed.contains(&rel) {
            bail!("{rel} is in the bundle but not in its manifest");
        }
    }
    println!(
        "contract bundle verified: server {} contract {} ({} files)",
        lock.server_version,
        lock.contract_version,
        listed.len()
    );
    Ok(())
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            out.extend(walk(&p)?);
        } else {
            out.push(p);
        }
    }
    Ok(out)
}

/// Downloads `purlay-contract-<tag>.tar.gz` from the server's GitHub release, checks
/// its `.sha256`, verifies the bundle, and updates the pin only for an explicit tag.
pub fn fetch(root: &Path, tag: Option<&str>) -> Result<()> {
    let (tag, pinned) = match tag {
        Some(tag) => (tag.to_string(), None),
        None => {
            let lock = Lock::read(root)?;
            (format!("v{}", lock.server_version), Some(lock))
        }
    };
    let bundles = root.join("Contract/bundle");
    std::fs::create_dir_all(&bundles)?;
    let staging = tempfile::tempdir_in(&bundles)?;
    let download = staging.path();
    let pattern = format!("purlay-contract-{tag}.tar.gz*");
    let status = Command::new("gh")
        .args(["release", "download", &tag, "--repo", "purlay/purlay", "--clobber", "-p", &pattern, "-D"])
        .arg(download)
        .status()
        .context("run gh (GitHub CLI)")?;
    if !status.success() {
        bail!("gh release download failed");
    }
    let archive = download.join(format!("purlay-contract-{tag}.tar.gz"));
    let sums = std::fs::read_to_string(download.join(format!("purlay-contract-{tag}.tar.gz.sha256")))?;
    let want = sums.split_whitespace().next().context("empty .sha256")?;
    let got = sha256_file(&archive)?;
    if got != want {
        bail!("archive digest {got} differs from the release's {want}");
    }
    let status = Command::new("tar").arg("-xzf").arg(&archive).arg("-C").arg(download).status()?;
    if !status.success() {
        bail!("tar failed");
    }
    install_release(root, staging, tag.trim_start_matches('v'), pinned)
}

fn install_release(root: &Path, staging: tempfile::TempDir, version: &str, pinned: Option<Lock>) -> Result<()> {
    let target = bundle_dir(root, version);
    let unpacked = staging.path().join(target.file_name().context("bundle directory name")?);
    let update_pin = pinned.is_none();
    let lock = match pinned {
        Some(lock) => lock,
        None => lock_from_bundle(&unpacked)?,
    };
    if lock.server_version != version {
        bail!("bundle version {} differs from requested version {version}", lock.server_version);
    }
    verify_bundle(&unpacked, &lock)?;
    if !target.exists() {
        std::fs::rename(&unpacked, &target)?;
    } else if verify_bundle(&target, &lock).is_err() {
        // Keep the prior directory recoverable if the move of the verified bundle fails.
        let previous = staging.path().join("previous");
        std::fs::rename(&target, &previous)?;
        if let Err(error) = std::fs::rename(&unpacked, &target) {
            if let Err(restore_error) = std::fs::rename(&previous, &target) {
                let kept = staging.keep();
                bail!("install failed ({error}); restore failed ({restore_error}); previous bundle is in {}", kept.display());
            }
            return Err(error).context("install verified release bundle");
        }
    }
    if update_pin {
        write_pin(root, &lock)?;
    }
    Ok(())
}

pub fn use_dir(root: &Path, dir: &Path) -> Result<()> {
    let manifest = crate::read_json(&dir.join("MANIFEST.json"))?;
    let version = manifest["serverVersion"].as_str().context("serverVersion")?;
    let target = bundle_dir(root, version);
    if target.exists() {
        std::fs::remove_dir_all(&target)?;
    }
    copy_dir(dir, &target)?;
    pin(root, &target)
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let p = e.path();
        if p.is_dir() {
            copy_dir(&p, &to.join(e.file_name()))?;
        } else {
            std::fs::copy(&p, to.join(e.file_name()))?;
        }
    }
    Ok(())
}

fn pin(root: &Path, dir: &Path) -> Result<()> {
    let lock = lock_from_bundle(dir)?;
    verify_bundle(dir, &lock)?;
    write_pin(root, &lock)
}

fn lock_from_bundle(dir: &Path) -> Result<Lock> {
    let manifest = crate::read_json(&dir.join("MANIFEST.json"))?;
    Ok(Lock {
        bundle_format: manifest["format"].as_u64().context("format")?,
        contract_version: manifest["contractVersion"].as_u64().context("contractVersion")?,
        manifest_sha256: sha256_file(&dir.join("MANIFEST.json"))?,
        server_version: manifest["serverVersion"].as_str().context("serverVersion")?.to_string(),
    })
}

fn write_pin(root: &Path, lock: &Lock) -> Result<()> {
    lock.write(root)?;
    println!("pinned server {} (manifest {})", lock.server_version, lock.manifest_sha256);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn example_bundle(dir: &Path, version: &str, content: &str) -> Result<Lock> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join("contract.json"), content)?;
        let manifest = serde_json::json!({
            "format": 1,
            "contractVersion": 1,
            "serverVersion": version,
            "files": [{
                "path": "contract.json",
                "sha256": sha256_file(&dir.join("contract.json"))?,
            }],
        });
        fs::write(dir.join("MANIFEST.json"), manifest.to_string())?;
        lock_from_bundle(dir)
    }

    #[test]
    fn a_pinned_fetch_installs_the_bundle_without_rewriting_the_lock() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let target = bundle_dir(root, "0.9.0");
        let bundles = target.parent().context("bundle parent")?;
        fs::create_dir_all(bundles)?;
        let staging = tempfile::tempdir_in(bundles)?;
        let locked = example_bundle(&staging.path().join("purlay-contract-v0.9.0"), "0.9.0", "original")?;
        locked.write(root)?;
        let lock_path = root.join("Contract/contract.lock");
        let original = format!("\n{}", fs::read_to_string(&lock_path)?);
        fs::write(&lock_path, &original)?;

        install_release(root, staging, "0.9.0", Some(Lock::read(root)?))?;
        assert_eq!(fs::read_to_string(&lock_path)?, original);
        assert_eq!(verify(root)?, target);
        Ok(())
    }

    #[test]
    fn a_mismatched_pinned_fetch_preserves_the_lock_and_installed_bundle() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let target = bundle_dir(root, "0.9.0");
        let locked = example_bundle(&target, "0.9.0", "original")?;
        locked.write(root)?;
        let lock_path = root.join("Contract/contract.lock");
        let original = fs::read(&lock_path)?;
        let staging = tempfile::tempdir_in(target.parent().context("bundle parent")?)?;
        example_bundle(&staging.path().join("purlay-contract-v0.9.0"), "0.9.0", "different")?;

        let error = install_release(root, staging, "0.9.0", Some(locked)).expect_err("locked digest must be enforced");
        assert!(error.to_string().contains("does not match the lock"), "{error:#}");
        assert_eq!(fs::read(&lock_path)?, original);
        assert_eq!(fs::read_to_string(target.join("contract.json"))?, "original");
        assert_eq!(verify(root)?, target);
        Ok(())
    }

    #[test]
    fn only_a_verified_explicit_release_updates_the_pin() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let previous = bundle_dir(root, "0.9.0");
        example_bundle(&previous, "0.9.0", "original")?.write(root)?;
        let bundles = previous.parent().context("bundle parent")?;
        let staging = tempfile::tempdir_in(bundles)?;
        let candidate = staging.path().join("purlay-contract-v0.9.1");
        example_bundle(&candidate, "0.9.1", "new")?;
        fs::write(candidate.join("contract.json"), "damaged")?;

        install_release(root, staging, "0.9.1", None).expect_err("damaged file must be refused");
        assert_eq!(verify(root)?, previous);

        let staging = tempfile::tempdir_in(bundles)?;
        example_bundle(&staging.path().join("purlay-contract-v0.9.1"), "0.9.1", "new")?;
        install_release(root, staging, "0.9.1", None)?;
        assert_eq!(verify(root)?, bundle_dir(root, "0.9.1"));
        Ok(())
    }

    #[test]
    fn a_verified_fetch_replaces_a_damaged_cached_bundle() -> Result<()> {
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let target = bundle_dir(root, "0.9.0");
        let locked = example_bundle(&target, "0.9.0", "original")?;
        locked.write(root)?;
        fs::write(target.join("contract.json"), "damaged")?;
        let staging = tempfile::tempdir_in(target.parent().context("bundle parent")?)?;
        example_bundle(&staging.path().join("purlay-contract-v0.9.0"), "0.9.0", "original")?;

        install_release(root, staging, "0.9.0", Some(locked))?;
        assert_eq!(verify(root)?, target);
        assert_eq!(fs::read_to_string(target.join("contract.json"))?, "original");
        Ok(())
    }
}
