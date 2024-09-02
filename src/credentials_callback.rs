use oid4vp::core::presentation_definition::PresentationDefinition;

use crate::common::*;
use crate::vdc_collection::Credential;

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

/// Type alias for mapping input descriptor ids to matching credentials
/// stored in the VDC collection. This mapping is used to provide a
/// shared state between native code and the rust code, to select
/// the appropriate credentials for a given input descriptor.
pub type InputDescriptorCredentialMap = HashMap<String, Vec<Arc<Credential>>>;

/// A clonable and thread-safe reference to the input descriptor credential map.
pub type InputDescriptorCredentialMapRef = Arc<RwLock<InputDescriptorCredentialMap>>;

/// A clonable and thread-safe reference to the selected credential map.
pub type SelectedCredentialMapRef = Arc<RwLock<HashMap<String, Vec<Uuid>>>>;

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum CredentialCallbackError {
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
}

#[derive(Debug, uniffi::Object)]
pub struct RequestedField {
    pub(crate) name: String,
    pub(crate) required: bool,
    pub(crate) retained: bool,
    pub(crate) credential_type: Option<CredentialType>,
    pub(crate) purpose: Option<String>,
    /// If the requested field is for an input descriptor,
    /// this field will contain the id of the input descriptor.
    pub(crate) input_descriptor_id: Option<String>,
    /// Permit the presentation of the requested field.
    ///
    /// This field should be set to true when the requested field is permitted.
    ///
    /// This field is protected by a RwLock to allow for inner mutability, enabling
    /// the native code to call the [RequestedField::set_permission] method, which
    /// will set the permit to true.
    pub(crate) permit: RwLock<bool>,
}

impl RequestedField {
    pub fn new(
        name: String,
        required: bool,
        retained: bool,
        credential_type: Option<CredentialType>,
        purpose: Option<String>,
        input_descriptor_id: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            name,
            required,
            retained,
            credential_type,
            purpose,
            input_descriptor_id,
            // By default the permit is false, and must be set
            // to true by the native code, using the [RequestedField::set_permission] method.
            permit: RwLock::new(false),
        })
    }

    /// This method will return true or false depending on whether the requested field is permitted.
    ///
    /// However, if the field is required and the permission is false (denied),
    /// this method will return a permission denied error.
    pub fn is_permitted(&self) -> Result<bool, CredentialCallbackError> {
        // Attempt to read the `permit` field.
        let permit = self
            .permit
            .read()
            .map_err(|_| CredentialCallbackError::RwLockError)?;

        // If the permit is false and the field is required, return an error.
        if !*permit && self.required {
            return Err(CredentialCallbackError::PermissionDenied);
        }

        Ok(*permit)
    }

    /// Return the input descriptor id.
    pub fn input_descriptor_id(&self) -> Option<String> {
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

    /// Return the field credential type
    pub fn credential_type(&self) -> Option<CredentialType> {
        self.credential_type.clone()
    }

    /// Return the purpose of the requested field.
    pub fn purpose(&self) -> Option<String> {
        self.purpose.clone()
    }

    /// Set the permission to present the requested field.
    ///
    /// By default requested fields are not permitted, and this method must explicitly
    /// be called by the native code to set the permit to true.
    ///
    /// If the field is required and the permission is false (denied),
    /// this method will return a permission denied error.
    pub fn set_permission(
        self: Arc<Self>,
        permission: bool,
    ) -> Result<(), CredentialCallbackError> {
        // Attempt to write to the `permit` field.
        let mut permit = self
            .permit
            .write()
            .map_err(|_| CredentialCallbackError::RwLockError)?;

        if self.required && !permission {
            return Err(CredentialCallbackError::PermissionDenied);
        }

        *permit = permission;

        Ok(())
    }
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct PermissionRequest {
    inner: PresentationDefinition,
    // selective disclosure mapping
}

impl AsRef<PresentationDefinition> for PermissionRequest {
    fn as_ref(&self) -> &PresentationDefinition {
        &self.inner
    }
}

impl From<&PresentationDefinition> for PermissionRequest {
    fn from(inner: &PresentationDefinition) -> Self {
        Self {
            // Creating a clone to avoid lifetime limitations
            // in the uniffi generated code.
            inner: inner.clone(),
        }
    }
}

impl PermissionRequest {
    pub fn new(inner: &PresentationDefinition) -> Arc<Self> {
        Arc::new(Self::from(inner))
    }
}

#[uniffi::export]
impl PermissionRequest {
    /// Return the requested fields from the presentation definition.
    ///
    /// This method is intended to be used by the native code to determine which fields
    /// are being requested by the verifier.
    ///
    ///
    /// By default the permission of the field is false.
    /// the native code should explicitly set the permission
    /// to true, based on the holder's decision.
    ///
    /// Use the [RequestedField::set_permission] method to
    /// set the permission.
    pub fn requested_fields(&self) -> Vec<Arc<RequestedField>> {
        self.inner
            // TODO: need to check submission requirements and group constraints.
            // For now, we are checking only the input descriptor constraints fields.
            .input_descriptors()
            .iter()
            .filter_map(|input_descriptor| {
                input_descriptor.constraints().fields().map(|fields| {
                    fields.iter().map(|field| {
                        field.requested_fields().into_iter().map(|name| {
                            RequestedField::new(
                                name,
                                field.is_required(),
                                field.intent_to_retain(),
                                field.credential_type(),
                                field.purpose().map(ToOwned::to_owned),
                                Some(input_descriptor.id().to_owned()),
                            )
                        })
                    })
                })
            })
            .flatten()
            .flatten()
            .collect()
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
    inner: Vec<Arc<RequestedField>>,
}

impl PermissionResponse {
    /// Return the requested fields from the permission response.
    pub fn requested_fields(&self) -> &Vec<Arc<RequestedField>> {
        &self.inner
    }
}

/// Select Credential Request
///
/// This struct is used to represent the request to select credentials for a given presentation submission.
///
///
#[derive(Debug, uniffi::Object)]
pub struct SelectCredentialRequest {
    // Credentials provides a mapping from input descriptor id to credential
    credentials: InputDescriptorCredentialMapRef,
    // selected is a mapping from input descriptor id to a list of selected credential IDs.
    selected: SelectedCredentialMapRef,
}

impl From<InputDescriptorCredentialMap> for SelectCredentialRequest {
    fn from(credentials: InputDescriptorCredentialMap) -> Self {
        Self {
            credentials: Arc::new(RwLock::new(credentials)),
            selected: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl SelectCredentialRequest {
    /// Create a new instance of the SelectCredentialRequest.
    pub fn new(credential_map: InputDescriptorCredentialMap) -> Arc<Self> {
        Arc::new(Self::from(credential_map))
    }

    /// This method will return the filtered the credentials based on the selected credential ids
    /// set by the native code using the [SelectCredentialRequest::select_credential] method.
    pub fn into_response(
        self: Arc<Self>,
    ) -> Result<SelectCredentialResponse, CredentialCallbackError> {
        let mut inner_credentials = self
            .credentials
            .write()
            .map_err(|_| CredentialCallbackError::RwLockError)?;

        for (id, selection) in self
            .selected
            .read()
            .map_err(|_| CredentialCallbackError::RwLockError)?
            .iter()
        {
            let credentials = inner_credentials.get_mut(id).ok_or(
                CredentialCallbackError::InputDescriptorNotFound(id.to_owned()),
            )?;

            for selected_cred in selection {
                // retain only the selected credentials
                credentials.retain(|cred| cred.id() == *selected_cred);
            }
        }

        Ok(SelectCredentialResponse {
            inner: self.credentials.clone(),
        })
    }
}

#[uniffi::export]
impl SelectCredentialRequest {
    // TODO: Add an accessor method to display the credentials.

    /// Select a credential from the mapping, supplying the input descriptor id and the credential id.
    pub fn select_credential(
        &self,
        input_descriptor_id: String,
        credential_id: Uuid,
    ) -> Result<(), CredentialCallbackError> {
        let mut selected = self
            .selected
            .write()
            .map_err(|_| CredentialCallbackError::RwLockError)?;

        let selected_credentials = selected.entry(input_descriptor_id).or_insert_with(Vec::new);
        selected_credentials.push(credential_id);

        Ok(())
    }
}

#[derive(Debug, uniffi::Object)]
pub struct SelectCredentialResponse {
    // The selected credentials is a mapping from input descriptor
    // id to a filtered list of selected credentials.
    pub(crate) inner: InputDescriptorCredentialMapRef,
}

#[uniffi::export]
impl SelectCredentialResponse {
    /// Create a select credential response from the selected credentials
    /// in the select credential request.
    ///
    /// Used by the native code to create a response from the selected credentials.
    #[uniffi::constructor]
    pub fn from_request(
        request: Arc<SelectCredentialRequest>,
    ) -> Result<Arc<Self>, CredentialCallbackError> {
        Ok(Arc::new(request.into_response()?))
    }
}

/// This is a callback interface for credential operations, defined by the native code.
///
/// For example, this is used to provide methods for the client to select a credential to present,
/// retrieved from the wallet.
#[uniffi::export(with_foreign)]
pub trait CredentialCallbackInterface: Send + Sync + Debug {
    /// Permit the verifier to request the information defined in the presentation definition.
    ///
    /// This method is called during the presentation request, passing the required fields
    /// from the presentation definition. The verifier should return a boolean indicating whether
    /// the verifier can present the requested information.
    ///
    /// A [PresentationRequest] is passed to the native code to allow the user to identify
    /// which fields are being requested, and whether those fields will be retained.
    ///
    /// The presentation request DOES NOT submit credentials or user data, but rather is used by the
    /// user interface of the holder to determine whether the user will permit the verifier to
    /// receive the requested the information.
    ///
    /// If the user denies a required field request, the verifier should return a [CredentialCallbackError::PermissionDenied]
    fn permit_presentation(
        &self,
        request: Arc<PermissionRequest>,
    ) -> Result<Arc<PermissionResponse>, CredentialCallbackError>;

    /// Select which credentials to present provided a list of matching credentials.
    ///
    /// This is called by the client to select which credentials to present to the verifier. Multiple credentials
    /// may satisfy the request, and the client should select the most appropriate credentials to present.
    ///
    /// This method should return a vector of credential UUIDs that the client wishes to present.
    fn select_credentials(
        &self,
        request: Arc<SelectCredentialRequest>,
    ) -> Arc<SelectCredentialResponse>;
}
