//! TUN-mode interception path (US-011).
//!
//! `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` cannot intercept statically-linked
//! binaries (notably Go) because they make syscalls directly and never resolve
//! libc symbols. TUN mode brings up a virtual network interface and routes the
//! process's outbound packets through the agent's SOCKS5 proxy instead, so it
//! works regardless of how the binary is linked.
//!
//! Bringing up the device and running the packet→SOCKS5 forwarder needs elevated
//! privileges and a platform device (`/dev/net/tun` on Linux, `utun` on macOS).
//! This module owns the dispatch and prerequisite checks; the device/tun2socks
//! engine is tracked as remaining work.

use std::str::FromStr;

use tracing::{info, warn};

/// How the agent intercepts the local process's outbound traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterceptMode {
    /// Preload shim (default). Hooks connect()/getaddrinfo() via the layer lib.
    #[default]
    Preload,
    /// TUN device. Routes outbound packets to the SOCKS5 proxy; covers static
    /// binaries the preload shim cannot.
    Tun,
}

impl FromStr for InterceptMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "preload" | "ld-preload" | "ld_preload" => Ok(Self::Preload),
            "tun" | "tun-tap" | "tuntap" => Ok(Self::Tun),
            other => {
                anyhow::bail!("unknown --mode {other:?}: expected 'preload' or 'tun'")
            }
        }
    }
}

/// Activate TUN-based interception, routing outbound traffic to the agent's
/// SOCKS5 proxy on `socks5_port`. Validates platform prerequisites first.
pub async fn activate(socks5_port: u16) -> anyhow::Result<()> {
    ensure_supported()?;

    info!(
        socks5_port,
        "TUN interception requested — routing outbound packets to the SOCKS5 proxy"
    );

    // The TUN device + packet→SOCKS5 forwarder backend is not yet wired in. We
    // surface the requirement clearly rather than silently behaving like preload
    // mode, so static binaries are not mistakenly assumed covered.
    warn!(
        "TUN device backend is not yet available; outbound traffic must reach the \
         SOCKS5 proxy on 127.0.0.1:{socks5_port}. Static binaries are not covered \
         until the device forwarder lands. Use --mode preload for dynamically \
         linked binaries."
    );

    Ok(())
}

fn ensure_supported() -> anyhow::Result<()> {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        Ok(())
    } else {
        anyhow::bail!("TUN mode is only supported on Linux and macOS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intercept_mode_defaults_to_preload() {
        assert_eq!(InterceptMode::default(), InterceptMode::Preload);
    }

    #[test]
    fn intercept_mode_parses_known_values() {
        assert_eq!(
            "preload".parse::<InterceptMode>().unwrap(),
            InterceptMode::Preload
        );
        assert_eq!(
            "ld-preload".parse::<InterceptMode>().unwrap(),
            InterceptMode::Preload
        );
        assert_eq!("tun".parse::<InterceptMode>().unwrap(), InterceptMode::Tun);
        assert_eq!("TUN".parse::<InterceptMode>().unwrap(), InterceptMode::Tun);
        assert_eq!(
            " Tun-Tap ".parse::<InterceptMode>().unwrap(),
            InterceptMode::Tun
        );
    }

    #[test]
    fn intercept_mode_rejects_unknown_values() {
        let err = "iptables".parse::<InterceptMode>().unwrap_err();
        assert!(err.to_string().contains("expected 'preload' or 'tun'"));
    }
}
