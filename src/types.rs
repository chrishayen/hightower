use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub public_ip: String,
    pub public_port: u16,
    pub local_ip: String,
    pub local_port: u16,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegistrationRequest<'a> {
    pub public_key_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegistrationResponse {
    pub node_id: String,
    pub token: String,
    pub gateway_public_key_hex: String,
    pub assigned_ip: String,
}
