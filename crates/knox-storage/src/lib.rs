use blake3::Hasher;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use getrandom::getrandom;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

const DB_MAGIC_V1: &[u8; 4] = b"PCDB";
const DB_MAGIC_V2: &[u8; 4] = b"PCD2";
const KEY_FILE: &str = "db.key";

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
            file.flush().map_err(|e| e.to_string())?;
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
            let nonce = &buf[4..28];
            let cipher = &buf[28..];
            let plain = decrypt_record(&self.key, key, nonce, cipher)?;
            return Ok(Some(plain));
        }
        if buf.len() >= 4 + 32 && &buf[..4] == DB_MAGIC_V1 {
            let allow_legacy = std::env::var("KNOX_DB_ALLOW_LEGACY_V1")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow_legacy {
                return Err("legacy db record format disabled; set KNOX_DB_ALLOW_LEGACY_V1=1 for one-time migration".to_string());
            }
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
        file.write_all(DB_MAGIC_V2).map_err(|e| e.to_string())?;
        file.write_all(&nonce).map_err(|e| e.to_string())?;
        file.write_all(&cipher).map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
        fs::rename(tmp, path).map_err(|e| e.to_string())?;
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
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: value,
                aad: record_key,
            },
        )
        .map_err(|_| "db encrypt failed".to_string())
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
    let mut nonce_arr = [0u8; 24];
    nonce_arr.copy_from_slice(nonce);
    let aead = XChaCha20Poly1305::new(key.into());
    aead.decrypt(
        XNonce::from_slice(&nonce_arr),
        Payload {
            msg: cipher,
            aad: record_key,
        },
    )
    .map_err(|_| "db decrypt failed".to_string())
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
