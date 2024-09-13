use crate::{CredentialType, KeyAlias, Uuid};
use serde::{Deserialize, Serialize};

/// An individual credential.
#[derive(Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Credential {
    /// The local ID of this credential.
    pub id: Uuid,
    /// The format of this credential.
    pub format: CredentialFormat,
    /// The type of this credential.
    pub r#type: CredentialType,
    /// The raw payload of this credential. The encoding depends on the format.
    pub payload: Vec<u8>,
    /// The alias of the key that is authorized to present this credential.
    pub key_alias: Option<KeyAlias>,
}

/// The format of the credential.
#[derive(uniffi::Enum, PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    MsoMdoc,
    JwtVcJson,
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,
    LdpVc,
    #[serde(untagged)]
    Other(String), // For ease of expansion.
}

#[cfg(test)]
mod test {
    use super::*;

    #[rstest::rstest]
    #[case::mso_mdoc(r#""mso_mdoc""#, CredentialFormat::MsoMdoc)]
    #[case::jwt_vc_json(r#""jwt_vc_json""#, CredentialFormat::JwtVcJson)]
    #[case::jwt_vc_json_ld(r#""jwt_vc_json-ld""#, CredentialFormat::JwtVcJsonLd)]
    #[case::ldp_vc(r#""ldp_vc""#, CredentialFormat::LdpVc)]
    #[case::other(r#""something_else""#, CredentialFormat::Other("something_else".into()))]
    fn credential_format_roundtrips(#[case] expected: String, #[case] value: CredentialFormat) {
        let serialized = serde_json::to_string(&value).unwrap();
        assert_eq!(expected, serialized);

        let roundtripped: CredentialFormat = serde_json::from_str(&serialized).unwrap();

        assert_eq!(value, roundtripped);
    }

    #[test]
    fn credential_format_roundtrips_other() {
        let value = CredentialFormat::Other("mso_mdoc".into());

        let serialized = serde_json::to_string(&value).unwrap();
        assert_eq!(r#""mso_mdoc""#, serialized);

        let roundtripped: CredentialFormat = serde_json::from_str(&serialized).unwrap();

        assert_eq!(CredentialFormat::MsoMdoc, roundtripped);
    }
}
