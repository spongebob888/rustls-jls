use std::net::SocketAddr;
use std::string::{String, ToString};

use crate::jls::server;
use crate::JlsConfig;

use crate::log::trace;

/// Jls Server Configuration
#[derive(Clone, Debug, Default)]
pub struct JlsServerConfig {
    /// Jls password and iv
    pub inner: JlsConfig,
    /// upstream address, for example, example.com:443
    /// If empty, forwarding will be disabled
    pub upstream_addr: Option<String>,
    /// server name for upstream, if empty, server name check will be skipped
    pub upstream_sni: Option<String>,
}

impl JlsServerConfig {
    /// Create a new jls server configuration
    pub fn new(pwd: String, iv: String, 
        upstream_addr: Option<String>,
        mut upstream_sni: Option<String>) -> Self {
        match upstream_addr.clone() {
            Some(addr) =>  {
                if let Err(_) = addr.parse::<SocketAddr>() {
                    if upstream_sni.is_none() {
                        upstream_sni = addr.split(":").next().map(|s| s.to_string());
                    }
                }
            },
            None => {
                upstream_sni = None;
            }
        }
        JlsServerConfig {
            inner: JlsConfig::new(&pwd, &iv),
            upstream_addr: upstream_addr,
            upstream_sni: upstream_sni,
        }
    }

    /// Verify whether client server name match upstream domain name
    pub(crate) fn check_server_name(&self, server_name: Option<&str>) -> bool {
        if let Some(upstream) = &self.upstream_sni {
            let ret = server_name == Some(upstream);
            trace!("[jls] server name mateches:{}", ret);
            return ret;
        } else {
            trace!("[jls] upstream sni not found");
            return true;
        }
    }
}
