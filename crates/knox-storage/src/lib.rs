use blake3::Hasher;
use getrandom::getrandom;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

const DB_MAGIC_V1: &[u8; 4] = b"PCDB";
const DB_MAGIC_V2: &[u8; 4] = b"PCD2";
const DB_MAGIC_V3: &[u8; 4] = b"PCD3";
const KEY_FILE: &str = "db.key";

fn sync_writes_enabled() -> bool {
    matches!(
        std::env::var("KNOX_DB_SYNC_WRITES")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes")
    )
}

pub struct Db {
    root: PathBuf,
    key: [u8; 32],
}

impl Db {
    pub fn open(path: &str) -> Result<Self, String> {
        let root = PathBuf::from(path);
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let key_path = root.join(KEY_FILE);
        let key = if key_path.exists() {
            let mut buf = Vec::new();
            let mut file = fs::File::open(&key_path).map_err(|e| e.to_string())?;
            file.read_to_end(&mut buf).map_err(|e| e.to_string())?;
            if buf.len() != 32 {
                return Err("db key invalid length".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&buf);
            harden_file_permissions(&key_path);
            key
        } else {
            let mut key = [0u8; 32];
            getrandom(&mut key).map_err(|e| e.to_string())?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)
                .map_err(|e| e.to_string())?;
            file.write_all(&key).map_err(|e| e.to_string())?;
            if sync_writes_enabled() {
                file.flush().map_err(|e| e.to_string())?;
            }
            harden_file_permissions(&key_path);
            key
        };
        Ok(Self { root, key })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let path = self.key_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        if buf.len() >= 4 + 24 + 16 && &buf[..4] == DB_MAGIC_V2 {
            return Err(
                "db record uses retired xchacha format; wipe ledger and resync with current binaries"
                    .to_string(),
            );
        }
        if buf.len() >= 4 + 24 + 16 && &buf[..4] == DB_MAGIC_V3 {
            let nonce = &buf[4..28];
            let cipher = &buf[28..];
            let plain = decrypt_record(&self.key, key, nonce, cipher)?;
            return Ok(Some(plain));
        }
        if buf.len() >= 4 + 32 && &buf[..4] == DB_MAGIC_V1 {
            // Legacy v1 records can still exist on long-lived nodes. Read + migrate
            // in-place so older block ranges remain servable during rolling upgrades.
            let mac = &buf[4..36];
            let value = &buf[36..];
            let expected = keyed_hash_legacy(&self.key, value);
            if mac.ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
                return Err("db corruption detected (mac mismatch)".to_string());
            }
            // Opportunistically migrate legacy plaintext record into encrypted v2.
            let _ = self.put(key, value);
            return Ok(Some(value.to_vec()));
        }
        Ok(Some(buf))
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        let path = self.key_path(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("tmp");
        let mut file = fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut nonce = [0u8; 24];
        getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let cipher = encrypt_record(&self.key, key, &nonce, value)?;
        file.write_all(DB_MAGIC_V3).map_err(|e| e.to_string())?;
        file.write_all(&nonce).map_err(|e| e.to_string())?;
        file.write_all(&cipher).map_err(|e| e.to_string())?;
        if sync_writes_enabled() {
            file.flush().map_err(|e| e.to_string())?;
        }
        fs::rename(tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), String> {
        for entry in fs::read_dir(&self.root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(KEY_FILE) {
                continue;
            }
            if path.is_dir() {
                fs::remove_dir_all(&path).map_err(|e| e.to_string())?;
            } else {
                fs::remove_file(&path).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    fn key_path(&self, key: &[u8]) -> PathBuf {
        let hex = hex_encode(key);
        let prefix = &hex[0..2.min(hex.len())];
        self.root.join(prefix).join(hex)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn keyed_hash_legacy(key: &[u8; 32], value: &[u8]) -> blake3::Hash {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(b"knox-db-mac");
    hasher.update(value);
    hasher.finalize()
}

fn encrypt_record(
    key: &[u8; 32],
    record_key: &[u8],
    nonce: &[u8; 24],
    value: &[u8],
) -> Result<Vec<u8>, String> {
    let keystream = stream_bytes(key, nonce, record_key, value.len());
    let mut ciphertext = vec![0u8; value.len()];
    for (idx, byte) in value.iter().enumerate() {
        ciphertext[idx] = *byte ^ keystream[idx];
    }
    let tag = auth_tag(key, nonce, record_key, &ciphertext);
    let mut out = Vec::with_capacity(16 + ciphertext.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_record(
    key: &[u8; 32],
    record_key: &[u8],
    nonce: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>, String> {
    if nonce.len() != 24 {
        return Err("db nonce length invalid".to_string());
    }
    if cipher.len() < 16 {
        return Err("db ciphertext too short".to_string());
    }
    let mut nonce_arr = [0u8; 24];
    nonce_arr.copy_from_slice(nonce);
    let expected = auth_tag(key, &nonce_arr, record_key, &cipher[16..]);
    let mut found = [0u8; 16];
    found.copy_from_slice(&cipher[..16]);
    if expected.ct_eq(&found).unwrap_u8() == 0 {
        return Err("db decrypt failed".to_string());
    }
    let keystream = stream_bytes(key, &nonce_arr, record_key, cipher.len().saturating_sub(16));
    let mut plain = vec![0u8; cipher.len().saturating_sub(16)];
    for (idx, byte) in cipher[16..].iter().enumerate() {
        plain[idx] = *byte ^ keystream[idx];
    }
    Ok(plain)
}

fn stream_bytes(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(b"knox-lattice-stream-v1");
    hasher.update(nonce);
    hasher.update(&(aad.len() as u32).to_le_bytes());
    hasher.update(aad);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; len];
    reader.fill(&mut out);
    out
}

fn auth_tag(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], cipher: &[u8]) -> [u8; 16] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(b"knox-lattice-auth-v1");
    hasher.update(nonce);
    hasher.update(&(aad.len() as u32).to_le_bytes());
    hasher.update(aad);
    hasher.update(&(cipher.len() as u32).to_le_bytes());
    hasher.update(cipher);
    let digest = hasher.finalize();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&digest.as_bytes()[..16]);
    tag
}

fn harden_file_permissions(path: &PathBuf) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod tests {
    use super::Db;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_db_dir(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        p.push(format!("knox-storage-test-{tag}-{ts}"));
        p.to_string_lossy().to_string()
    }

    #[test]
    fn encrypted_round_trip_and_key_binding() {
        let dir = tmp_db_dir("roundtrip");
        let db = Db::open(&dir).expect("open db");
        db.put(b"alpha", b"secret-value").expect("put");
        assert_eq!(
            db.get(b"alpha").expect("get"),
            Some(b"secret-value".to_vec())
        );
        assert_eq!(db.get(b"beta").expect("get"), None);
    }
}
