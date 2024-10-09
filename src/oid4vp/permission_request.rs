use oid4vp::core::presentation_definition::PresentationDefinition;

use crate::common::*;
use crate::credential::{Credential, ParsedCredential};

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

/// Type alias for mapping input descriptor ids to matching credentials
/// stored in the VDC collection. This mapping is used to provide a
/// shared state between native code and the rust code, to select
/// the appropriate credentials for a given input descriptor.
pub type InputDescriptorCredentialMap = HashMap<String, Vec<Credential>>;

/// A clonable and thread-safe reference to the input descriptor credential map.
pub type InputDescriptorCredentialMapRef = Arc<RwLock<InputDescriptorCredentialMap>>;

/// A clonable and thread-safe reference to the selected credential map.
pub type SelectedCredentialMapRef = Arc<RwLock<HashMap<String, Vec<Uuid>>>>;

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum PermissionRequestError {
    /// Permission denied for requested presentation.
    #[error("Permission denied for requested presentation.")]
    PermissionDenied,

    /// RwLock error
    #[error("RwLock error.")]
    RwLockError,

    /// Credential not found for input descriptor id.
    #[error("Credential not found for input descriptor id: {0}")]
    CredentialNotFound(String),

    /// Input descriptor not found for input descriptor id.
    #[error("Input descriptor not found for input descriptor id: {0}")]
    InputDescriptorNotFound(String),

    /// Invalid selected credential for requested field. Selected
    /// credential does not match optional credentials.
    #[error("Selected credential type, {0}, does not match requested credential types: {1}")]
    InvalidSelectedCredential(String, String),

    /// Credential Presentation Error
    ///
    /// failed to present the credential.
    #[error("Credential Presentation Error: {0}")]
    CredentialPresentation(String),
}

#[derive(Debug, uniffi::Object)]
pub struct RequestedField {
    /// A unique ID for the requested field
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) required: bool,
    pub(crate) retained: bool,
    pub(crate) purpose: Option<String>,
    pub(crate) input_descriptor_id: String,
}

impl RequestedField {
    /// Construct a new requested field given the required parameters. This method is exposed as
    /// public, however, it is likely that the `from_definition` method will be used to construct
    /// requested fields from a presentation definition.
    ///
    /// See [RequestedField::from_definition] to return a vector of requested fields
    /// according to a presentation definition.
    pub fn new(
        name: String,
        required: bool,
        retained: bool,
        purpose: Option<String>,
        input_descriptor_id: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: Uuid::new_v4(),
            name,
            required,
            retained,
            purpose,
            input_descriptor_id,
        })
    }

    /// Return the unique ID for the request field.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Return the input descriptor id.
    pub fn input_descriptor_id(&self) -> String {
        self.input_descriptor_id.clone()
    }
}

/// Public methods for the RequestedField struct.
#[uniffi::export]
impl RequestedField {
    /// Return the field name
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Return the field required status
    pub fn required(&self) -> bool {
        self.required
    }

    /// Return the field retained status
    pub fn retained(&self) -> bool {
        self.retained
    }

    /// Return the purpose of the requested field.
    pub fn purpose(&self) -> Option<String> {
        self.purpose.clone()
    }
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct PermissionRequest {
    definition: PresentationDefinition,
    credentials: Vec<Arc<ParsedCredential>>,
}

impl PermissionRequest {
    pub fn new(
        definition: PresentationDefinition,
        credentials: Vec<Arc<ParsedCredential>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            definition,
            credentials,
        })
    }
}

#[uniffi::export]
impl PermissionRequest {
    /// Return the filtered list of credentials that matched
    /// the presentation definition.
    pub fn credentials(&self) -> Vec<Arc<ParsedCredential>> {
        self.credentials.clone()
    }

    /// Return the requested fields for a given credential id.
    pub fn requested_fields(&self) -> Vec<Arc<RequestedField>> {
        self.definition
            .input_descriptors()
            .iter()
            .flat_map(|descriptor| {
                descriptor.constraints().fields().iter().map(|field| {
                    let purpose = field.purpose().map(ToOwned::to_owned);
                    let name = field
                        .name()
                        .map(ToOwned::to_owned)
                        // TODO: Add an "unknown field" if the name is not provided.
                        // Consider skipping or erroring on unknown fields.
                        .unwrap_or_default();
                    let required = field.is_required();
                    let retained = field.intent_to_retain();

                    RequestedField::new(
                        name,
                        required,
                        retained,
                        purpose,
                        descriptor.id().to_string(),
                    )
                })
            })
            .collect::<Vec<Arc<RequestedField>>>()
    }

    /// Construct a new permission response for the given credential.
    pub fn create_permission_response(
        &self,
        selected_credential: Arc<ParsedCredential>,
    ) -> Arc<PermissionResponse> {
        Arc::new(PermissionResponse {
            selected_credential,
            presentation_definition: self.definition.clone(),
        })
    }

    /// Return the purpose of the presentation request.
    pub fn purpose(&self) -> Option<String> {
        self.definition.purpose().map(ToOwned::to_owned)
    }
}

/// This struct is used to represent the response to a permission request.
///
/// Use the [PermissionResponse::new] method to create a new instance of the PermissionResponse.
///
/// The Requested Fields are created by calling the [PermissionRequest::requested_fields] method, and then
/// explicitly setting the permission to true or false, based on the holder's decision.
#[derive(Debug, Clone, uniffi::Object)]
pub struct PermissionResponse {
    pub selected_credential: Arc<ParsedCredential>,
    pub presentation_definition: PresentationDefinition,
}
