use super::crypto::crypto_utils::validate_hash;
use const_format::formatcp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::ops::Deref;
use std::str::FromStr;

// ref: https://www.w3.org/TR/did-core/#did-syntax
static PAC_ENCODED: &str = r"%[0-9A-Fa-f]{2}";
static IDCHAR: &str = formatcp!(r"[a-zA-Z0-9.\-_{PAC_ENCODED}]");
static METHOD_CHAR: &str = r"[a-zA-Z0-9]";
static METHOD_PAT: &str = formatcp!(r"{METHOD_CHAR}+");
static SPECIFIC_ID_PAT: &str = formatcp!(r"({IDCHAR}*:)*{IDCHAR}+");
static DID_PAT: &str =
    formatcp!(r"^did:(?<method_name>{METHOD_PAT}):(?<method_specific_id>{SPECIFIC_ID_PAT})$");

pub static DIDWEBVH_PLACEHOLDER: &str = "{SCID}";

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum DidError {
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error("Failed to parse did")]
    InvalidFormat,
    #[error("Failed to parse method name")]
    InvalidMethodName,
    #[error("Failed to parse method specific id")]
    InvalidMethodSpecificId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Did {
    method_name_position: usize,
    method_specific_id_position: usize,
    inner: String,
}

impl Did {
    pub fn new(method: &str, identifier: &str) -> Result<Self, DidError> {
        let re_method = regex::Regex::new(METHOD_PAT)?;
        let re_id = regex::Regex::new(SPECIFIC_ID_PAT)?;
        if !re_method.is_match(method) {
            return Err(DidError::InvalidMethodName);
        }

        if !re_id.is_match(identifier) {
            return Err(DidError::InvalidMethodSpecificId);
        }
        let method_name_position = 4 + method.len();
        let method_specific_id_position = method_name_position + 1 + identifier.len();
        Ok(Self {
            method_name_position,
            method_specific_id_position,
            inner: format!("did:{}:{}", method, identifier),
        })
    }

    pub fn into_inner(self) -> String {
        self.inner
    }

    pub fn get_method(&self) -> &str {
        &self.inner[4..self.method_name_position]
    }

    pub fn get_method_specific_id(&self) -> &str {
        &self.inner[(self.method_name_position + 1)..self.method_specific_id_position]
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl From<DidWebvh> for Did {
    fn from(did: DidWebvh) -> Self {
        did.did
    }
}

fn verify_did(did: &str) -> Result<(usize, usize), DidError> {
    let re = regex::Regex::new(DID_PAT)?;
    let caps = re.captures(did).ok_or(DidError::InvalidFormat)?;
    Ok((
        caps.name("method_name")
            .ok_or(DidError::InvalidMethodName)?
            .end(),
        caps.name("method_specific_id")
            .ok_or(DidError::InvalidMethodSpecificId)?
            .end(),
    ))
}

impl FromStr for Did {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (method_name_position, method_specific_id_position) = verify_did(s)?;
        Ok(Self {
            method_name_position,
            method_specific_id_position,
            inner: s.to_string(),
        })
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let (method_name_position, method_specific_id_position) =
            verify_did(&s).map_err(|_| serde::de::Error::custom("Invalid Did Format"))?;
        Ok(Self {
            method_name_position,
            method_specific_id_position,
            inner: s,
        })
    }
}

impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.inner)
    }
}

impl Deref for Did {
    type Target = str;

    fn deref(&self) -> &str {
        &self.inner
    }
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum DidWebvhError {
    #[error(transparent)]
    DidError(DidError),
    #[error("Invalid SCID")]
    InvalidSCID,
    #[error("Invalid domain segment")]
    InvalidDomain,
    #[error("Invalid path segment")]
    InvalidPath,
}

impl From<DidError> for DidWebvhError {
    fn from(err: DidError) -> Self {
        Self::DidError(err)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DidWebvh {
    did: Did,
    scid: String,
    uri: String,
}

impl DidWebvh {
    pub fn new(scid: &str, uri: &str) -> Result<Self, DidWebvhError> {
        if scid.is_empty() {
            return Err(DidWebvhError::InvalidSCID);
        }

        if scid != DIDWEBVH_PLACEHOLDER && !validate_hash(scid) {
            return Err(DidWebvhError::InvalidSCID);
        }

        if uri.is_empty() {
            return Err(DidWebvhError::InvalidDomain);
        }
        // uri is not contain '/', need to use ":" as path separator
        if uri.contains('/') {
            return Err(DidWebvhError::InvalidPath);
        }
        let did = Did::new("webvh", &format!("{}:{}", scid, uri))?;
        Ok(Self {
            did,
            scid: scid.to_string(),
            uri: uri.to_string(),
        })
    }

    pub fn get_scid(&self) -> &str {
        &self.scid
    }

    pub fn get_uri(&self) -> &str {
        &self.uri
    }

    pub fn get_did(&self) -> &Did {
        &self.did
    }

    pub fn replace_scid(&self, scid: &str) -> Self {
        Self {
            did: Did::new("webvh", &format!("{}:{}", scid, self.uri)).unwrap(),
            scid: scid.to_string(),
            uri: self.uri.to_string(),
        }
    }

    pub fn did_to_https(&self) -> String {
        let mut parts: Vec<String> = self.uri.split(':').map(|s| s.to_string()).collect();
        if parts[0].contains("%3A") {
            parts[0] = parts[0].replace("%3A", ":");
        }
        format!("https://{}", parts.join("/"))
    }
}

impl TryFrom<Did> for DidWebvh {
    type Error = DidWebvhError;

    fn try_from(did: Did) -> Result<Self, Self::Error> {
        if did.get_method() != "webvh" {
            return Err(DidWebvhError::DidError(DidError::InvalidMethodName));
        }
        let parts: Vec<&str> = did.get_method_specific_id().split(':').collect();
        if parts.len() < 2 {
            return Err(DidWebvhError::InvalidPath);
        }
        Self::new(parts[0], parts[1..].join(":").as_str())
    }
}

impl FromStr for DidWebvh {
    type Err = DidWebvhError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did: Did = s.parse()?;
        if did.get_method() != "webvh" {
            return Err(DidWebvhError::DidError(DidError::InvalidMethodName));
        }
        let parts: Vec<&str> = did.get_method_specific_id().split(':').collect();
        // parsed scid and domain
        // eg. ["scid", "example.com%3A8000", "path", "to", "resource"]
        if parts.len() < 2 {
            return Err(DidWebvhError::DidError(DidError::InvalidMethodSpecificId));
        }
        // domain may be have path
        Self::new(parts[0], parts[1..].join(":").as_str())
    }
}

impl<'de> Deserialize<'de> for DidWebvh {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse()
            .map_err(|_| serde::de::Error::custom("Invalid Did Format"))
    }
}

impl Deref for DidWebvh {
    type Target = str;

    fn deref(&self) -> &str {
        &self.did.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_example() -> Result<(), DidError> {
        let did = Did::new("example", "hogehoge")?;
        assert_eq!(did.get_method(), "example");
        assert_eq!(did.get_method_specific_id(), "hogehoge");
        assert_eq!(did.to_string(), "did:example:hogehoge");

        let did = "did:example:hogehoge".parse::<Did>().unwrap();
        assert_eq!(did.get_method(), "example");
        assert_eq!(did.get_method_specific_id(), "hogehoge");
        Ok(())
    }

    #[test]
    fn test_did_webvh_in_did() -> Result<(), DidError> {
        let did = Did::new(
            "webvh",
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com:path:to:resource",
        )?;
        assert_eq!(did.get_method(), "webvh");
        assert_eq!(
            did.get_method_specific_id(),
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com:path:to:resource"
        );
        assert_eq!(
            did.to_string(),
            "did:webvh:QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com:path:to:resource"
        );

        let did = "did:webvh:QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com%3A8000:path:to:resource"
            .parse::<Did>()
            .unwrap();
        assert_eq!(did.get_method(), "webvh");
        assert_eq!(
            did.get_method_specific_id(),
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com%3A8000:path:to:resource"
        );

        Ok(())
    }

    #[test]
    fn test_did_error() {
        assert_eq!(
            Did::new("", "example").unwrap_err(),
            DidError::InvalidMethodName
        );
        assert_eq!(
            Did::new("web", "").unwrap_err(),
            DidError::InvalidMethodSpecificId
        );
    }

    #[test]
    fn test_did_webvh() -> Result<(), DidWebvhError> {
        let did = DidWebvh::new(
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr",
            "example.com:path:to:resource",
        )?;
        assert_eq!(
            did.get_scid(),
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr"
        );
        assert_eq!(did.get_uri(), "example.com:path:to:resource");
        assert_eq!(did.did_to_https(), "https://example.com/path/to/resource");

        let did = "did:webvh:QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com%3A8000:path:to:resource"
            .parse::<DidWebvh>()
            .unwrap();
        assert_eq!(
            did.get_scid(),
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr"
        );
        assert_eq!(did.get_uri(), "example.com%3A8000:path:to:resource");
        assert_eq!(
            did.did_to_https(),
            "https://example.com:8000/path/to/resource"
        );

        let did = Did::new(
            "webvh",
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com:path:to:resource",
        )?;
        let did_webvh = DidWebvh::try_from(did)?;
        assert_eq!(
            did_webvh.get_scid(),
            "QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr"
        );
        assert_eq!(did_webvh.get_uri(), "example.com:path:to:resource");
        assert_eq!(
            did_webvh.did_to_https(),
            "https://example.com/path/to/resource"
        );

        Ok(())
    }

    #[test]
    fn test_did_webvh_error() {
        assert_eq!(
            DidWebvh::new("", "path/to/resource").unwrap_err(),
            DidWebvhError::InvalidSCID
        );
        assert_eq!(
            DidWebvh::new("example.com%3A8000", "").unwrap_err(),
            DidWebvhError::InvalidSCID
        );
        assert_eq!(
            "did:QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:webvh:example.com%3A8000:path/to/resource"
                .parse::<DidWebvh>()
                .unwrap_err(),
            DidWebvhError::DidError(DidError::InvalidFormat)
        );
        assert_eq!(
            "did:webvh:example.com%3A8000"
                .parse::<DidWebvh>()
                .unwrap_err(),
            DidWebvhError::DidError(DidError::InvalidMethodSpecificId)
        );
        assert_eq!(
            "did:webvh:QmdEjpG2gwEWZAx8YjBrw7mF1iuCqgrMh8S63M7PaC1Ldr:example.com%3A8000:path/to/resource"
                .parse::<DidWebvh>()
                .unwrap_err(),
            DidWebvhError::DidError(DidError::InvalidFormat)
        );
    }
}
