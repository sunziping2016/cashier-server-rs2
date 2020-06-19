use crate::{
    api::{
        api_v1,
        app_state::AppState,
    },
    config::StartConfig,
    queries::Query,
    actors::server_subscriber::ServerSubscriber,
};
use actix::Actor;
use actix_files as fs;
use actix_web::{
    web, App, HttpServer,
    middleware::Logger,
};
use err_derive::Error;
use log::error;
use redis::RedisError;
use tokio::sync::RwLock;
use tokio_postgres::{
    Error as PostgresError,
    NoTls,
};

#[derive(Debug, Error)]
pub enum StartError {
    #[error(display = "{}", _0)]
    Db(#[error(source)]#[error(from)] PostgresError),
    #[error(display = "{}", _0)]
    Io(#[error(source)] #[error(from)] std::io::Error),
    #[error(display = "{}", _0)]
    Redis(#[error(source)] #[error(from)] RedisError)
}

pub type Result<T> = std::result::Result<T, StartError>;

pub async fn start(config: &StartConfig) -> Result<()> {
    let (client, connection) = tokio_postgres::connect(&config.db, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("connection error: {}", e);
        }
    });
    let query = Query::new(&client).await;
    let redis_client = redis::Client::open(&config.redis[..])?;
    let redis_connection = redis_client.get_async_connection().await?;
    let subscriber = ServerSubscriber::new(
        redis_client.get_async_connection().await?,
        redis_connection.into_pubsub()
    ).start();
    let app_data = web::Data::new(AppState {
        config: config.clone(),
        db: RwLock::from(client),
        query,
        subscriber,
    });
    let media_serve = config.media.serve;
    let media_url = config.media.url.clone();
    let media_root = config.media.root.clone();
    HttpServer::new(move || {
        let mut app = App::new()
            .wrap(Logger::default())
            .configure(api_v1(&app_data));
        if media_serve {
            app = app.service(fs::Files::new(&media_url, &media_root))
        }
        app
    })
        .bind(&config.bind)?
        .run()
        .await?;
    Ok(())
}