use crate::{
    api::{
        api_v1,
        app_state::AppState,
    },
    config::StartConfig,
    queries::Query,
};
use actix_files as fs;
use actix_web::{
    web, App, HttpServer,
    middleware::Logger,
};
use err_derive::Error;
use log::error;
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
    let app_data = web::Data::new(AppState {
        config: config.clone(),
        db: RwLock::from(client),
        query
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