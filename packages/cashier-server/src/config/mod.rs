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