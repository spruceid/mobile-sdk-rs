use crate::vdc_collection::Credential;

use std::fmt::Debug;
use std::sync::Arc;

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum CredentialCallbackError {
    #[error("Permission denied for requested presentation.")]
    PermissionDenied,
}

/// This is a callback interface for credential operations, defined by the native code.
///
/// For example, this is used to provide methods for the client to select a credential to present,
/// retrieved from the wallet.
#[uniffi::export(callback_interface)]
pub trait CredentialCallbackInterface: Send + Sync + Debug {
    /// Permit the verifier to request the information defined in the presentation definition.
    ///
    /// This method is called during the presentation request, passing the required fields
    /// from the presentation definition. The verifier should return a boolean indicating whether
    /// the verifier can present the requested information.
    ///
    /// The native client should implement this method, returning a vector of booleans indicating
    /// whether the requested information can be presented.
    ///
    /// the format of the requested_information is a vector of strings, each string is a field name
    /// that the verifier is requesting, e.g. ["Name", "Date Of Birth", "Address"]
    ///
    /// If the user denies the a field request, the verifier should return a [CredentialCallbackError::PermissionDenied]
    fn permit_presentation(
        &self,
        requested_fields: Vec<String>,
    ) -> Result<(), CredentialCallbackError>;

    /// Select which credentials to present provided a list of matching credentials.
    ///
    /// This is called by the client to select which credentials to present to the verifier. Multiple credentials
    /// may satisfy the request, and the client should select the most appropriate credentials to present.
    fn select_credentials(&self, credentials: Vec<Arc<Credential>>) -> Vec<Arc<Credential>>;
}
