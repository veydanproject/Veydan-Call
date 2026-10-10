//! An invitation to a private node, and the credentials of a device.
//!
//! ```text
//! operator   vcall ctl invite --uses 1 --ttl 7d --label "Anna's phone"
//!            → veydan://call-node/<id>?a=<address%3Aport>&t=<token>
//! app        POST /v1/invite  InviteRequest {token, name} → DeviceCredentials {device_id, secret, …}
//!            keeps device_id and secret in its secret store, shows them as
//!            `access.device` in every request that takes `access`
//! operator   vcall ctl devices            what the node let in, by label
//!            vcall ctl revoke <device_id> the device is a stranger again
//! ```
//!
//! The token of an invitation is for the exchange only: it opens nothing
//! else, it may be used so many times and until a day, and the node keeps
//! only its hash. The credentials of a device last until they are revoked.
//! An access key (`VCALL_ACCESS_KEYS`) opens the same doors; a node may
//! have keys, devices or both.

use serde::{Deserialize, Serialize};

/// The type of the link: `veydan://call-node/<id>?a=<address>&t=<token>`.
pub const LINK_TYPE: &str = "call-node";
/// The query parameters of the link: the control address, the token.
pub const PARAM_ADDR: &str = "a";
pub const PARAM_TOKEN: &str = "t";

/// Bytes of a token and of a device's secret (the hex is twice that), and
/// of a device's id.
pub const TOKEN_BYTES: usize = 24;
pub const SECRET_BYTES: usize = 32;
pub const DEVICE_ID_BYTES: usize = 16;
/// How long a label of an invitation or a device may be.
pub const MAX_LABEL: usize = 64;

/// What the app sends with the token of a link.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRequest {
    /// `t` of the link, 48 hex characters.
    pub token: String,
    /// What the device calls itself, for `vcall ctl devices`: a short
    /// name without a line break; cut to [`MAX_LABEL`]. Nothing of the
    /// person: the node needs no name to let a device in.
    #[serde(default)]
    pub name: String,
}

/// What the node answers: the credentials the device shows from now on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCredentials {
    /// 32 hex characters: the node's name for the device.
    pub device_id: String,
    /// 64 hex characters: shown as `access.device.secret`; the node keeps
    /// its hash only, so it cannot be read back from the node.
    pub secret: String,
    /// The node, `address:port#id`, as the app pins and names it: the
    /// address of the link, the id the TLS was pinned to.
    pub node: String,
    /// The label the operator gave the invitation, if any: what the
    /// app may show the node as.
    #[serde(default)]
    pub label: String,
}

/// Percent-encoding as the app's links want it: everything but letters,
/// digits and `-_.~` (what `vlink link` does for a bridge's address).
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The link of an invitation: `veydan://call-node/<id>?a=<address>&t=<token>`,
/// `address` being `ip:port` of the node's control channel, percent-encoded.
pub fn link(node_id: &str, control_addr: &str, token: &str) -> String {
    format!("veydan://{LINK_TYPE}/{node_id}?{PARAM_ADDR}={}&{PARAM_TOKEN}={}", percent_encode(control_addr), percent_encode(token))
}

/// A label as the node keeps it: one line, at most [`MAX_LABEL`] characters.
pub fn label(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(MAX_LABEL).collect::<String>().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_is_written_as_the_app_takes_it() {
        let id = "ab".repeat(32);
        let token = "cd".repeat(TOKEN_BYTES);
        assert_eq!(link(&id, "203.0.113.7:8443", &token), format!("veydan://call-node/{id}?a=203.0.113.7%3A8443&t={token}"));
        assert_eq!(link(&id, "[2001:db8::1]:443", &token), format!("veydan://call-node/{id}?a=%5B2001%3Adb8%3A%3A1%5D%3A443&t={token}"));
        assert_eq!(label(" Anna's\nphone "), "Anna'sphone");
        assert_eq!(label(&"x".repeat(100)).len(), MAX_LABEL);
        let request: InviteRequest = serde_json::from_str(r#"{"token":"abc"}"#).unwrap();
        assert_eq!(request.name, "");
        let creds = DeviceCredentials { device_id: "01".repeat(16), secret: "02".repeat(32), node: format!("203.0.113.7:8443#{id}"), label: String::new() };
        let back: DeviceCredentials = serde_json::from_str(&serde_json::to_string(&creds).unwrap()).unwrap();
        assert_eq!(back, creds);
    }
}
