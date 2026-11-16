use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct Storage;

impl Storage {
    pub fn atomic_write_secure<P: AsRef<Path>>(target_path: P, data: &[u8]) -> io::Result<()> {
        let path = target_path.as_ref();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }

        if path.exists() {
            let mut backup_path = PathBuf::from(path);
            let ext = backup_path.extension().and_then(|s| s.to_str()).unwrap_or("");
            backup_path.set_extension(if ext.is_empty() { "bak".to_string() } else { format!("{ext}.bak") });
            let _ = fs::copy(path, backup_path);
        }

        let pid = std::process::id();
        let tmp_file_name = format!(".tmp.{}.{}", pid, rand::random::<u32>());
        let tmp_path = parent.join(tmp_file_name);

        {
            let mut file = File::create(&tmp_path)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let permissions = fs::Permissions::from_mode(0o600);
                file.set_permissions(permissions)?;
            }

            file.write_all(data)?;
            file.sync_all()?;
        }

        fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = fs::remove_file(&tmp_path);
        })?;

        Ok(())
    }

    pub fn read_secure<P: AsRef<Path>>(target_path: P) -> io::Result<Vec<u8>> {
        fs::read(target_path)
    }

    pub fn backup_wallet<P: AsRef<Path>, D: AsRef<Path>>(src: P, dst: D) -> io::Result<u64> {
        let data = fs::read(src.as_ref())?;
        Self::atomic_write_secure(dst.as_ref(), &data)?;
        Ok(data.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_write_and_read() {
        let dir = std::env::temp_dir().join(format!("agy_test_storage_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&dir);
        let test_file = dir.join("test_file.dat");

        let test_data = b"secret payload 12345";
        Storage::atomic_write_secure(&test_file, test_data).expect("write failed");

        let read_data = Storage::read_secure(&test_file).expect("read failed");
        assert_eq!(read_data, test_data);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&test_file).expect("metadata failed");
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let test_data_updated = b"updated payload 67890";
        Storage::atomic_write_secure(&test_file, test_data_updated).expect("update failed");

        let read_data_updated = Storage::read_secure(&test_file).expect("read failed");
        assert_eq!(read_data_updated, test_data_updated);

        let backup_file = dir.join("test_file.dat.bak");
        assert!(backup_file.exists());
        let backup_data = fs::read(backup_file).expect("read backup");
        assert_eq!(backup_data, test_data);

        let _ = fs::remove_dir_all(dir);
    }
}
