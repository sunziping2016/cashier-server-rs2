use chrono::Duration;
use lazy_static::lazy_static;

pub const JWT_SECRET_LENGTH: u32 = 256;
pub const JWT_EXPIRE: &str = "10 day";
pub const BCRYPT_COST: u32 = 10;

pub const AVATAR_FOLDER: &str = "images/avatars";
pub const AVATAR_FILENAME_LENGTH: usize = 24;

pub const CHANNEL_NAME: &str = "cashier-server-channel";

lazy_static! {
    pub static ref WEBSOCKET_HEARTBEAT_INTERVAL: Duration = Duration::seconds(30);
    pub static ref WEBSOCKET_CLIENT_TIMEOUT: Duration = Duration::minutes(1);
    pub static ref WEBSOCKET_PERMISSION_REFRESH_INTERVAL: Duration = Duration::minutes(2);
}
