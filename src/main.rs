use std::{env, fs::File, sync::Arc, thread, time::Duration};

use anyhow::{Result, anyhow};
use base64::prelude::*;
use log::{LevelFilter, error, info};
use serde::Deserialize;
use totp_rs::{Algorithm, Secret, TOTP};
use ureq::{
    Agent,
    config::{AutoHeaderValue, IpFamily},
};

fn main() -> Result<()> {
    env_logger::builder()
        .filter(None, LevelFilter::Error)
        .filter(Some(module_path!()), LevelFilter::Info)
        .init();

    let Config {
        hostname,
        domain,
        email,
        password,
        secret,
        cooldown,
    } = serde_json::from_reader(File::open("config.json")?)?;

    let user_agent = Arc::new(format!(
        "{}/{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    ));

    let agent_v4: Agent = Agent::config_builder()
        .user_agent(AutoHeaderValue::Provided(user_agent.clone()))
        .ip_family(IpFamily::Ipv4Only)
        .https_only(true)
        .build()
        .into();
    let agent_v6: Agent = Agent::config_builder()
        .user_agent(AutoHeaderValue::Provided(user_agent))
        .ip_family(IpFamily::Ipv6Only)
        .https_only(true)
        .build()
        .into();

    let url = format!("https://{hostname}/admin");
    let dns_a = format!("{url}/dns/custom/{domain}/A");
    let dns_aaaa = format!("{url}/dns/custom/{domain}/AAAA");

    let mut retries_left = 5;
    let auth = loop {
        let mut req = agent_v4.post(format!("{url}/login")).header(
            "authorization",
            format!(
                "Basic {}",
                BASE64_STANDARD.encode(format!("{email}:{password}"))
            ),
        );

        if let Some(secret) = &secret {
            let secret = Secret::Encoded(secret.to_string()).to_bytes()?;
            let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)?;
            req = req.header("x-auth-token", totp.generate_current()?);
        }

        match req.send_empty()?.body_mut().read_json::<LoginResponse>()? {
            LoginResponse::Ok {
                api_key,
                privileges,
                ..
            } if privileges.contains(&"admin".to_string()) => {
                break Ok(format!(
                    "Basic {}",
                    BASE64_STANDARD.encode(format!("{email}:{api_key}"))
                ));
            }
            LoginResponse::Ok { privileges, .. } => {
                break Err(anyhow!(
                    "API key does not have admin privileges: {privileges:?}"
                ));
            }
            LoginResponse::Invalid { reason } if retries_left > 0 => {
                retries_left -= 1;
                error!("Failed to get API key, retrying: {reason}");
            }
            LoginResponse::Invalid { reason } => {
                break Err(anyhow!("Failed to get API key: {reason}"));
            }
        }
    }?;

    loop {
        match agent_v4
            .put(&dns_a)
            .header("authorization", &auth)
            .send_empty()?
            .status()
        {
            code if code.is_success() => info!("Updated DNS A successfully."),
            code => error!("Failed to update DNS A: HTTP {code}"),
        }

        match agent_v6
            .put(&dns_aaaa)
            .header("authorization", &auth)
            .send_empty()?
            .status()
        {
            code if code.is_success() => {
                info!("Updated DNS AAAA successfully.")
            }
            code => error!("Failed to update DNS AAAA: HTTP {code}"),
        }

        thread::sleep(cooldown);
    }
}

#[derive(Deserialize)]
struct Config {
    hostname: String,
    domain: String,
    email: String,
    password: String,
    secret: Option<String>,
    #[serde(with = "humantime_serde")]
    cooldown: Duration,
}

/// Server response for the `/admin/login` API endpoint.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "status")]
enum LoginResponse {
    Ok {
        api_key: String,
        email: String,
        privileges: Vec<String>,
    },
    Invalid {
        reason: String,
    },
}
