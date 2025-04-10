use std::string::String;

use crate::JlsConfig;

use crate::log::trace;

/// Jls Server Configuration
#[derive(Clone, Debug, Default)]
pub struct JlsServerConfig {
    /// Jls password and iv
    pub inner: JlsConfig,
    /// upstream address, for example, example.com:443
    pub upstream_addr: Option<String>,
}

impl JlsServerConfig {
    /// Create a new jls server configuration
    pub fn new(pwd: &str, iv: &str, upstream_addr: &str) -> Self {
        JlsServerConfig {
            inner: JlsConfig::new(pwd, iv),
            upstream_addr: Some(upstream_addr.into()),
        }
    }

    /// Verify whether client server name match upstream domain name
    pub(crate) fn check_server_name(&self, server_name: Option<&str>) -> bool {
        if let Some(upstream) = &self.upstream_addr {
            let ret = if let Some(server_name) =server_name {
                upstream.split(":").into_iter().next() == Some(server_name)
            } else {
                false
            };
            trace!("[jls] server name mateches upstream_addr:{}", ret);
            return ret;
        } else {
            trace!("[jls] upstream url not found");
            return true;
        }
    }
}
