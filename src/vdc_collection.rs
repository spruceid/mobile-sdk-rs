/// Supported credential formats.
#[derive(PartialEq)]
pub enum CredentialFormat {
    MDoc,
    W3cJwtVc,
    W3cJwtVcJsonld,
    Other(String), // For ease of expansion.
}

/// Supported credential types.
#[derive(PartialEq)]
pub enum CredentialType {
    Iso18013_5_1mDl,
    VehicleTitle,
    Other(String), // For ease of expansion.
}

/// An individual credential.  These are mainly for internal use; access to them should go through `VdcCollection`,
/// below.
struct Credential {
    id: String, // Probably a UUID, perhaps we should make it one?
    format: CredentialFormat,
    ctype: CredentialType,
    payload: Vec<u8>, // The actual credential.
}

impl Credential {
    /// Create a new credential.
    fn new(
        id: &str,
        format: CredentialFormat,
        ctype: CredentialType,
        payload: Vec<u8>,
    ) -> Credential {
        Credential {
            id: id.to_string(),
            format,
            ctype,
            payload,
        }
    }

    /// Store a credential in secure storage if it has been modified.
    fn write_to_secure_storage(&mut self) {
        // TODO: implement.
    }

    /// Dump the contents of a credential.
    fn dump(&self) {
        println!("Credential {}", self.id);
        print!("    format:   ");
        match &self.format {
            CredentialFormat::MDoc => println!("MDoc"),
            CredentialFormat::W3cJwtVc => println!("W3C JWT VC"),
            CredentialFormat::W3cJwtVcJsonld => println!("W3C JWT VC JSON LD"),
            CredentialFormat::Other(x) => println!("Other ({})", x),
        }
        print!("    type:     ");
        match &self.ctype {
            CredentialType::Iso18013_5_1mDl => println!("ISO 18013.5.1 mDL"),
            CredentialType::VehicleTitle => println!("Vehicle Title"),
            CredentialType::Other(x) => println!("Other ({})", x),
        }
        if self.payload.is_empty() {
            println!("    payload:  missing?");
        }
    }
}

/// Verifiable Digital Credential Collection
///
/// This is the main interface to credentials.
pub struct VdcCollection {
    list: Vec<Credential>,
}

impl VdcCollection {
    /// Create a new credential set.
    pub fn new() -> VdcCollection {
        VdcCollection { list: Vec::new() }
    }

    /// Add a credential to the set.
    pub fn add(
        &mut self,
        id: &str,
        format: CredentialFormat,
        ctype: CredentialType,
        payload: Vec<u8>,
    ) {
        self.list.push(Credential::new(id, format, ctype, payload));
    }

    /// Load a credential from secure storage to the set.
    pub fn load_from_secure_storage(&mut self, path: &str) {
        // TODO: Implement.
        // Set dirty flag to false.
        println!("Save credential to {path}");
    }

    /// Load all credentials from secure storage.
    pub fn load_all_from_secure_storage(&mut self) {
        // TODO: Implement.
        // Iterate over available files calling self.load_from_secure_storage().
    }

    /// Save all credentials to secure storage.
    pub fn save_all_to_secure_storage(&mut self) {
        for cred in self.list.iter_mut() {
            cred.write_to_secure_storage(); // Will only actually write if the dirty flag is set.
        }
    }

    /// Get a list of all the credentials.
    pub fn all_entries(&mut self) -> Vec<String> {
        let mut r = Vec::new();

        for cred in self.list.iter_mut() {
            r.push(cred.id.clone());
        }

        r
    }

    /// Get a list of all the credentials that match a specified type.
    pub fn all_entries_by_type(&mut self, ctype: CredentialType) -> Vec<String> {
        let mut r = Vec::new();

        for cred in self.list.iter_mut() {
            if cred.ctype == ctype {
                r.push(cred.id.clone());
            }
        }

        r
    }

    /// Write all modified credentials to secure storage.
    pub fn write_to_secure_storage(&mut self) {
        for cred in self.list.iter_mut() {
            cred.write_to_secure_storage();
        }
    }

    /// Dump the contents of the credential set to the logger.
    pub fn dump(&mut self) {
        for cred in self.list.iter_mut() {
            cred.dump();
        }
    }
}
