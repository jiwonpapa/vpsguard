//! Uninstall release snapshot의 bounded tree와 exact restore 회귀입니다.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::tempdir;

use super::{BINARIES, UninstallReleaseStore};

#[test]
fn snapshots_and_restores_only_bounded_versioned_releases() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = tempdir()?;
    let root = temporary.path().join("root");
    let snapshots = temporary.path().join("snapshots");
    let release_root = root.join("usr/local/lib/vps-guard/releases");
    write_release(
        &release_root,
        "0123456789abcdef0123456789abcdef01234567",
        b"first",
    )?;
    write_release(
        &release_root,
        "89abcdef0123456789abcdef0123456789abcdef",
        b"second",
    )?;
    let store = UninstallReleaseStore::fixture(&root, &snapshots);

    let snapshot = store.create_snapshot()?;
    assert_eq!(snapshot.release_count, 2);
    assert_eq!(snapshot.binary_count, 8);
    store.verify_snapshot(&snapshot.path)?;

    fs::remove_dir_all(&release_root)?;
    let restored = store.restore_snapshot(&snapshot.path)?;
    assert_eq!(restored.release_count, 2);
    for name in BINARIES {
        assert_eq!(
            fs::read(
                release_root
                    .join("0123456789abcdef0123456789abcdef01234567/bin")
                    .join(name)
            )?,
            b"first"
        );
    }
    store.remove_snapshot(&snapshot.path)?;
    assert!(!snapshot.path.exists());
    Ok(())
}

#[test]
fn rejects_foreign_release_children_and_existing_restore_root()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let root = temporary.path().join("root");
    let snapshots = temporary.path().join("snapshots");
    let release_root = root.join("usr/local/lib/vps-guard/releases");
    let id = "0123456789abcdef0123456789abcdef01234567";
    write_release(&release_root, id, b"binary")?;
    fs::write(release_root.join(id).join("foreign"), b"no")?;
    let store = UninstallReleaseStore::fixture(&root, &snapshots);
    assert!(store.create_snapshot().is_err());

    fs::remove_file(release_root.join(id).join("foreign"))?;
    let snapshot = store.create_snapshot()?;
    assert!(store.restore_snapshot(&snapshot.path).is_err());
    Ok(())
}

fn write_release(root: &Path, id: &str, content: &[u8]) -> std::io::Result<()> {
    let bin = root.join(id).join("bin");
    fs::create_dir_all(&bin)?;
    for name in BINARIES {
        let path = bin.join(name);
        fs::write(&path, content)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
