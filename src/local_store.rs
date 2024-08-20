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
        match fs::create_dir(DATASTORE_PATH) {
            Ok(_) => {}                                                       // Success.
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {} // Success.
            Err(_) => return Err(StorageManagerError::InternalError),         // Fail.
        }

        match fs::write(gen_path(&key.0), value.0) {
            Ok(_) => Ok(()),
            Err(_) => Err(StorageManagerError::InternalError),
        }
    }

    /// Retrieve the value associated with a key.
    fn get(&self, key: Key) -> Result<Option<Value>, StorageManagerError> {
        match fs::read(gen_path(&key.0)) {
            Ok(x) => Ok(Some(Value(x))),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StorageManagerError::InternalError),
        }
    }

    /// List the available key/value pairs.
    fn list(&self) -> Result<Vec<Key>, StorageManagerError> {
        let mut keys = Vec::new();

        let files = match fs::read_dir(DATASTORE_PATH) {
            Ok(x) => x,
            Err(_) => return Err(StorageManagerError::InternalError),
        };

        for f in files.into_iter().flatten() {
            match f.file_name().to_str() {
                Some(x) => keys.push(Key(x.to_string())),
                None => return Err(StorageManagerError::InternalError),
            }
            //if let Some(x) = f.file_name().to_str() {
            //    keys.push(Key(x.to_string()));
            //}
        }

        Ok(keys)
    }

    /// Delete a given key/value pair from storage.
    fn remove(&self, key: Key) -> Result<(), StorageManagerError> {
        match fs::remove_file(gen_path(&key.0)) {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), // Removing something that isn't there shouldn't generate an error.
        }
    }
}

/// Generate the path to a file in the storage.
fn gen_path(file: &str) -> String {
    format!("{}/{}", DATASTORE_PATH, file)
}
