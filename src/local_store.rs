use crate::storage_manager::*;
use std::fs;

const DATASTORE_PATH: &str = "sprucekit-datastore";

/// A version of secure storage for debugging purposes, and as a minimal interface example.  Do not
/// use in production!  This encrypts nothing, uses a path relative to the current working directory,
/// and is generally cavalier about errors it encounters along the way.
pub struct LocalStore;

impl StorageManagerInterface for LocalStore {
    /// Add a key/value pair to storage.
    fn add(&self, key: Key, value: Value) -> Result<(), StorageManagerError> {
        // Make sure the directory exists.
        if let Ok(_) = fs::create_dir(DATASTORE_PATH) {}

        match fs::write(gen_path(key.0), value.0) {
            Ok(_) => Ok(()),
            Err(_) => Ok(()),
        }
    }

    /// Retrieve the value associated with a key.
    fn get(&self, key: Key) -> Result<Value, StorageManagerError> {
        match fs::read(gen_path(key.0)) {
            Ok(x) => Ok(Value(x)),
            Err(_) => Ok(Value(Vec::new())), // Should probably be a storage manager error.
        }
    }

    /// List the available key/value pairs.
    fn list(&self) -> Vec<Key> {
        let mut keys = Vec::new();
        let files = fs::read_dir(DATASTORE_PATH).unwrap();

        for f in files {
            if let Ok(x) = f {
                if let Some(x) = x.file_name().to_str() {
                    keys.push(Key(x.to_string()));
                }
            }
        }

        keys
    }

    /// Delete a given key/value pair from storage.
    fn remove(&self, key: Key) -> Result<(), StorageManagerError> {
        match fs::remove_file(gen_path(key.0)) {
            Ok(_) => Ok(()),
            Err(_) => Ok(()),
        }
    }
}

/// Generate the path to a file in the storage.
fn gen_path(file: String) -> String {
    format!("{}/{}", DATASTORE_PATH, file)
}
