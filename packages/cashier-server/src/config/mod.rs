use clap::{Arg, App};
use err_derive::Error;
use serde::{Serialize, Deserialize};
use shell_macro::shell;
use std::ffi::OsString;
use std::env;
use std::fs::File;
use std::path::Path;

pub const BUILD_VERSION: &str = shell!("git describe --tags $(git rev-list --tags --max-count=1)");
pub const BUILD_COMMIT_ID: &str = shell!("git log --format=\"%h\" -n 1");
pub const BUILD_TIME: &str = shell!("date +%F");
pub const AUTHORS: &str = shell!("git log --pretty=\"%an <%ae>\" | sort | uniq");

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(display = "{}", _0)]
    Io(#[error(source)] #[error(from)] std::io::Error),
    #[error(display = "{}", _0)]
    Json(#[error(source)] #[error(from)] serde_json::Error),
    #[error(display = "invalid subcommand")]
    InvalidSubcommand,
    #[error(display = "missing {} argument", _0)]
    MissingArgument(String),
}

#[derive(Debug, Clone)]
pub struct InitConfig {
    pub db: String,
    pub redis: String,
    pub reset: bool,
    pub superuser_username: Option<String>,
    pub superuser_password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediaConfig {
    pub root: String,
    pub url: String,
    pub serve: bool,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub server: String,
    pub sender: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GeoIpConfig {
    pub asn: Option<String>,
    pub asn_v6: Option<String>,
    pub city: Option<String>,
    pub city_v6: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StartConfig {
    pub db: String,
    pub redis: String,
    pub bind: String,
    pub site: String,
    pub media: MediaConfig,
    pub smtp: SmtpConfig,
    pub geoip: GeoIpConfig,
}

#[derive(Debug, Clone)]
pub enum Config {
    Init(InitConfig),
    Start(Box<StartConfig>),
}

#[derive(Serialize, Deserialize)]
pub struct MediaConfigFile {
    root: Option<String>,
    url: Option<String>,
    serve: Option<bool>,
}

impl Default for MediaConfigFile {
    fn default() -> Self {
        Self {
            root: None,
            url: None,
            serve: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SmtpConfigFile {
    pub server: Option<String>,
    pub sender: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for SmtpConfigFile {
    fn default() -> Self {
        Self {
            server: None,
            sender: None,
            username: None,
            password: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoIpConfigFile {
    pub asn: Option<String>,
    pub asn_v6: Option<String>,
    pub city: Option<String>,
    pub city_v6: Option<String>,
}

impl Default for GeoIpConfigFile {
    fn default() -> Self {
        Self {
            asn: None,
            asn_v6: None,
            city: None,
            city_v6: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFile {
    db: Option<String>,
    redis: Option<String>,
    bind: Option<String>,
    site: Option<String>,
    media: Option<MediaConfigFile>,
    smtp: Option<SmtpConfigFile>,
    geoip: Option<GeoIpConfigFile>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            db: None,
            redis: None,
            bind: None,
            site: None,
            media: None,
            smtp: None,
            geoip: None,
        }
    }
}

impl ConfigFile {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let json = File::open(path)?;
        Ok(serde_json::from_reader(&json)?)
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from(&mut env::args_os())
    }

    pub fn from<I, T>(itr: I) -> Result<Self, ConfigError>
        where
            I: IntoIterator<Item = T>,
            T: Into<OsString> + Clone,
    {
        let matches = App::new("cashier-server")
            .version(&format!("{} ({} {})", BUILD_VERSION.trim(),
                              BUILD_COMMIT_ID.trim(), BUILD_TIME.trim())[..])
            .author(&AUTHORS.trim().split('\n').collect::<Vec<&str>>().join(", ")[..])
            .about("Rust implementation for cashier server")
            .arg(Arg::with_name("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .about("Sets a custom config file")
                .takes_value(true))
            .arg(Arg::with_name("db")
                .long("db")
                .value_name("URL")
                .about("Sets the PostgreSQL connection")
                .takes_value(true))
            .arg(Arg::with_name("redis")
                .long("redis")
                .value_name("URL")
                .about("Sets the redis connection")
                .takes_value(true))
            .arg(Arg::with_name("bind")
                .long("bind")
                .value_name("ADDR:PORT")
                .about("Address to bind")
                .takes_value(true))
            .arg(Arg::with_name("site")
                .long("site")
                .about("Site for front-end")
                .takes_value(true))
            .arg(Arg::with_name("media-root")
                .long("media-root")
                .value_name("PATH")
                .about("Path to user-uploaded contents")
                .takes_value(true))
            .arg(Arg::with_name("media-url")
                .long("media-url")
                .value_name("URL")
                .about("URL prefix for user-uploaded contents")
                .takes_value(true))
            .arg(Arg::with_name("media-serve")
                .long("media-serve")
                .about("Serves user-uploaded contents"))
            .arg(Arg::with_name("smtp-server")
                .long("smtp-server")
                .about("SMTP server used to send e-mail")
                .takes_value(true))
            .arg(Arg::with_name("smtp-sender")
                .long("smtp-sender")
                .about("SMTP sender information in the \"From\" header")
                .takes_value(true))
            .arg(Arg::with_name("smtp-username")
                .long("smtp-username")
                .about("SMTP username for authentication")
                .takes_value(true))
            .arg(Arg::with_name("smtp-password")
                .long("smtp-password")
                .about("SMTP password for authentication")
                .takes_value(true))
            .arg(Arg::with_name("geoip-asn")
                .long("geoip-asn")
                .about("IPv4 ASN info database")
                .takes_value(true))
            .arg(Arg::with_name("geoip-asn-v6")
                .long("geoip-asn-v6")
                .about("IPv6 ASN info database")
                .takes_value(true))
            .arg(Arg::with_name("geoip-city")
                .long("geoip-city")
                .about("IPv4 City info database")
                .takes_value(true))
            .arg(Arg::with_name("geoip-city-v6")
                .long("geoip-city-v6")
                .about("IPv6 City info database")
                .takes_value(true))
            .subcommand(App::new("init")
                .about("Initializes all databases")
                .arg(Arg::with_name("reset")
                    .long("reset")
                    .about("Clears all databases before initialization. THIS IS DANGEROUS"))
                .arg(Arg::with_name("superuser-username")
                    .long("superuser-username")
                    .value_name("USERNAME")
                    .about("Creates a superuser and sets superuser's username")
                    .takes_value(true))
                .arg(Arg::with_name("superuser-password")
                    .long("superuser-password")
                    .value_name("PASSWORD")
                    .about("Sets superuser's password. Leaves empty to prompt from CLI")
                    .takes_value(true)))
            .subcommand(App::new("start")
                .about("Starts the server"))
            .get_matches_from(itr);
        let mut config_file = ConfigFile::default();
        if let Some(path) = matches.value_of("config") {
            config_file = ConfigFile::load(path)?;
        }
        config_file.db = matches.value_of("db").map(String::from).or(config_file.db);
        config_file.redis = matches.value_of("redis").map(String::from).or(config_file.redis);
        config_file.bind = matches.value_of("bind").map(String::from).or(config_file.bind);
        config_file.site = matches.value_of("site").map(String::from).or(config_file.site);
        let mut default_media_config_file = MediaConfigFile::default();
        let media_config_file = config_file.media.as_mut()
            .unwrap_or(&mut default_media_config_file);
        media_config_file.root = matches.value_of("media-root").map(String::from)
            .or_else(|| media_config_file.root.clone());
        media_config_file.url = matches.value_of("media-url").map(String::from)
            .or_else(|| media_config_file.url.clone());
        if matches.is_present("media-serve") {
            media_config_file.serve = Some(true);
        }
        let mut default_smtp_config_file = SmtpConfigFile::default();
        let smtp_config_file = config_file.smtp.as_mut()
            .unwrap_or(&mut default_smtp_config_file);
        smtp_config_file.server = matches.value_of("smtp-server").map(String::from)
            .or_else(|| smtp_config_file.server.clone());
        smtp_config_file.sender = matches.value_of("smtp-sender").map(String::from)
            .or_else(|| smtp_config_file.sender.clone());
        smtp_config_file.username = matches.value_of("smtp-username").map(String::from)
            .or_else(|| smtp_config_file.username.clone());
        smtp_config_file.password = matches.value_of("smtp-password").map(String::from)
            .or_else(|| smtp_config_file.password.clone());
        let mut default_geoip_config_file = GeoIpConfigFile::default();
        let geoip_config_file = config_file.geoip.as_mut()
            .unwrap_or(&mut default_geoip_config_file);
        geoip_config_file.asn = matches.value_of("geoip-asn").map(String::from)
            .or_else(|| geoip_config_file.asn.clone());
        geoip_config_file.asn_v6 = matches.value_of("geoip-asn-v6").map(String::from)
            .or_else(|| geoip_config_file.asn_v6.clone());
        geoip_config_file.city = matches.value_of("geoip-city").map(String::from)
            .or_else(|| geoip_config_file.city.clone());
        geoip_config_file.city_v6 = matches.value_of("geoip-city-v6").map(String::from)
            .or_else(|| geoip_config_file.city_v6.clone());
        match matches.subcommand() {
            ("init", Some(sub_matches)) => Ok(Config::Init(InitConfig {
                db: config_file.db
                    .ok_or_else(|| ConfigError::MissingArgument("database".into()))?,
                redis: config_file.redis
                    .ok_or_else(|| ConfigError::MissingArgument("redis".into()))?,
                reset: sub_matches.is_present("reset"),
                superuser_username: sub_matches.value_of("superuser-username").map(String::from),
                superuser_password: sub_matches.value_of("superuser-password").map(String::from),
            })),
            ("start", Some(_)) => Ok(Config::Start(Box::new(StartConfig {
                db: config_file.db
                    .ok_or_else(|| ConfigError::MissingArgument("database".into()))?,
                redis: config_file.redis
                    .ok_or_else(|| ConfigError::MissingArgument("redis".into()))?,
                bind: config_file.bind
                    .ok_or_else(|| ConfigError::MissingArgument("bind".into()))?,
                site: config_file.site
                    .ok_or_else(|| ConfigError::MissingArgument("site".into()))?,
                media: MediaConfig {
                    root: media_config_file.root.clone()
                        .ok_or_else(|| ConfigError::MissingArgument("media.root".into()))?,
                    url: media_config_file.url.clone()
                        .ok_or_else(|| ConfigError::MissingArgument("media.url".into()))?,
                    serve: media_config_file.serve.contains(&true),
                },
                smtp: SmtpConfig {
                    server: smtp_config_file.server.clone()
                        .ok_or_else(|| ConfigError::MissingArgument("smtp.server".into()))?,
                    sender: smtp_config_file.sender.clone()
                        .ok_or_else(|| ConfigError::MissingArgument("smtp.sender".into()))?,
                    username: smtp_config_file.username.clone(),
                    password: smtp_config_file.password.clone(),
                },
                geoip: GeoIpConfig {
                    asn: geoip_config_file.asn.clone(),
                    asn_v6: geoip_config_file.asn_v6.clone(),
                    city: geoip_config_file.city.clone(),
                    city_v6: geoip_config_file.city_v6.clone(),
                },
            }))),
            _ => Err(ConfigError::InvalidSubcommand)
        }
    }
}
