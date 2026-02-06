use std::net::SocketAddr;
use std::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;

use crate::jls::{JlsUser, server};
use crate::JlsConfig;

use crate::log::trace;

/// Jls Server Configuration
#[derive(Clone, Debug, Default)]
pub struct JlsServerConfig {
    /// enable JLS or a fall back to normal TLS
    pub enable: bool,
    /// Jls password and iv
    pub users: Vec<JlsUser>,
    /// upstream address, for example, example.com:443
    /// If empty, forwarding will be disabled
    pub upstream_addr: Option<String>,
    /// server name for upstream, if empty, server name check will be skipped
    pub upstream_sni: Option<String>,
    /// Limit the rate of JLS forwarding
    /// This is not done in rustls but in quinn or tokio-rustls
    pub rate_limit: u64,
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
            enable: true,
            users: vec![JlsUser::new(&pwd, &iv)],
            upstream_addr: upstream_addr,
            upstream_sni: upstream_sni,
            rate_limit: u64::MAX,
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
    /// Adding JLS config for a new user
    pub fn add_user(mut self, pwd: String, iv: String) -> Self {
        self.users.push(JlsUser::new(&pwd, &iv));
        self
    }
    /// setting upstream address and get default server name if viable
    pub fn with_upstream_addr(mut self, addr: String) -> Self {
        self.upstream_addr = Some(addr.clone());
        // If string is an ip address, we use this as the upstream sni
        if addr.parse::<SocketAddr>().is_err() && self.upstream_sni.is_none() {
            self.upstream_sni = addr.split(":").next().map(|s| s.to_string());
        }
        self
    }
    /// setting server name authentication check
    pub fn with_server_name(mut self, server_name: String) -> Self {
        self.upstream_sni = Some(server_name);
        self
    }
    /// setting rate limit for JLS forwarding
    pub fn with_rate_limit(mut self, rate_limit: u64) -> Self {
        self.rate_limit = rate_limit;
        self
    }
}
