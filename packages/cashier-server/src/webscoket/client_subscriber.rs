use crate::{
    webscoket::{
        main_subscriber::UpdateSubscribe,
        push_messages::PushMessage,
    },
    api::{
        app_state::AppState,
        extractors::auth::Auth,
    },
    constants::{
        WEBSOCKET_HEARTBEAT_INTERVAL,
        WEBSOCKET_CLIENT_TIMEOUT,
        WEBSOCKET_PERMISSION_REFRESH_INTERVAL,
    },
    queries::{
        users::PermissionTree,
        errors::Error as QueryError,
    },
};
use actix::{
    Actor, Handler, AsyncContext, Running, StreamHandler, ActorContext,
    Message, WrapFuture, ActorFuture, fut, SpawnHandle, ResponseActFuture,
};
use actix_web::web;
use actix_web_actors::ws;
use chrono::{DateTime, Utc, NaiveDateTime};
use derive_more::From;
use log::{info, error, warn};
use serde::{Serialize, Deserialize};
use std::{fmt, collections::HashSet, result::Result, convert::Infallible};
use crate::queries::users::PermissionTreeItem;

const MUST_INCLUDE_SUBJECT: &[&str] = &[
    "user-updated", // for block
    "user-deleted",
    "jwt-deleted",
    "user-role-created",
    "user-role-deleted",
    "role-permission-created",
    "role-permission-deleted",
];

const REMOVED_SUFFIX: &str = "-self";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PermissionUpdatedMessage {
    permissions: Vec<PermissionTreeItem>,
    claims: Option<Claims>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status")]
#[serde(rename_all = "kebab-case")]
enum UpdateTokenResponseStatus {
    Ok,
    InvalidToken {
        error: String,
    },
    UserBlocked,
    TokenRevoked,
    InvalidUser,
    InternalError,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateTokenResponse {
    status: UpdateTokenResponseStatus,
}

#[derive(Debug, Serialize, Deserialize, From, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
enum InnerClientResponseMessage {
    UpdateToken(UpdateTokenResponse),
    DeliverMessageFailed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ClientResponseMessage {
    request_id: u32,
    message: InnerClientResponseMessage,
}

#[derive(Debug, Serialize, Deserialize, From, Message, Clone)]
#[rtype(result = "()")]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
enum ClientPushMessage {
    PushMessage(PushMessage),
    PermissionUpdatedMessage(PermissionUpdatedMessage),
    ResponseMessage(ClientResponseMessage),
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "Result<UpdateTokenResponse, Infallible>")]
#[serde(rename_all = "camelCase")]
struct UpdateTokenRequest {
    jwt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, From, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
enum InnerClientRequestMessage {
    UpdateToken(UpdateTokenRequest),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[derive(Message)]
#[rtype(result = "Result<(), Infallible>")]
#[serde(rename_all = "camelCase")]
struct ClientRequestMessage {
    request_id: u32,
    message: InnerClientRequestMessage,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    user_id: i32,
    jwt_id: i32,
    expires_at: DateTime<Utc>,
}

#[derive(Message)]
#[rtype(result = "Result<(), Infallible>")]
pub struct FullyReloadPermissions;

#[derive(Message)]
#[rtype(result = "Result<(), Infallible>")]
pub struct ReloadPermissions;

pub struct ClientSubscriber {
    app_data: web::Data<AppState>,
    permissions: PermissionTree,
    claims: Option<Claims>,
    last_heartbeat: DateTime<Utc>,
    expire_timer: Option<SpawnHandle>,
}

impl fmt::Debug for ClientSubscriber {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("ClientSubscriber")
            .field("claims", &self.claims)
            .field("last_heartbeat", &self.last_heartbeat)
            .finish()
    }
}

impl ClientSubscriber {
    pub fn new(app_data: &web::Data<AppState>, auth: &Auth) -> Self {
        Self {
            app_data: app_data.clone(),
            permissions: PermissionTree::default(),
            claims: auth.claims.as_ref().map(|x| Claims {
                user_id: x.uid,
                jwt_id: x.jti,
                expires_at: DateTime::from_utc(NaiveDateTime::from_timestamp(x.exp, 0), Utc),
            }),
            last_heartbeat: Utc::now(),
            expire_timer: None,
        }
    }
}

impl Actor for ClientSubscriber {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let heartbeat_interval = WEBSOCKET_HEARTBEAT_INTERVAL.to_std().unwrap();
        let permission_refresh_interval = WEBSOCKET_PERMISSION_REFRESH_INTERVAL.to_std().unwrap();
        let client_timeout = *WEBSOCKET_CLIENT_TIMEOUT;
        ctx.run_interval(heartbeat_interval, move |act, ctx| {
            if Utc::now() - act.last_heartbeat > client_timeout {
                info!("Websocket heartbeat timeout, disconnecting");
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
        ctx.run_interval(permission_refresh_interval, move |_act, ctx| {
            if let Err(e) = ctx.address().try_send(FullyReloadPermissions) {
                error!("refresh FullyReloadSubjectsAndClaims error: {}", e);
                ctx.stop();
            }
        });
        if let Err(e) = ctx.address().try_send(FullyReloadPermissions) {
            error!("initial FullyReloadSubjectsAndClaims error: {}", e);
            ctx.stop();
        }
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        if let Err(e) = self.app_data.subscriber.try_send(UpdateSubscribe {
            client: ctx.address().recipient(),
            subjects: HashSet::new(),
        }) {
            error!("stopping error: {}", e);
        }
        Running::Stop
    }
}

impl Handler<PushMessage> for ClientSubscriber {
    type Result = Result<(), Infallible>;

    fn handle(&mut self, msg: PushMessage, ctx: &mut Self::Context) -> Self::Result {
        if let Err(e) = ctx.address().try_send::<ClientPushMessage>(msg.into()) {
            error!("send ClientPushMessage to self error: {}", e)
        }
        Ok(())
        // TODO: update permission
    }
}

impl Handler<ClientPushMessage> for ClientSubscriber {
    type Result = ();

    fn handle(&mut self, msg: ClientPushMessage, ctx: &mut Self::Context) -> Self::Result {
        match serde_json::to_string(&msg) {
            Ok(msg) => ctx.text(msg),
            Err(e) => error!("ClientPushMessage serialize error: {}", e),
        }
    }
}

impl Handler<FullyReloadPermissions> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, _msg: FullyReloadPermissions, _ctx: &mut Self::Context) -> Self::Result {
        let app_data = self.app_data.clone();
        let user_id = self.claims.as_ref().map(|x| x.user_id);
        Box::new(async move {
            app_data.query.user
                    .fetch_permission_tree(&*app_data.db.read().await, user_id)
                    .await
        }
            .into_actor(self)
            .then(|permissions, act, ctx| {
                match permissions {
                    Ok(permissions) => {
                        if act.permissions != permissions {
                            act.permissions = permissions;
                            if let Err(e) = ctx.address().try_send(ReloadPermissions) {
                                error!("send ReloadSubjectsAndClaims to self error: {}", e);
                                ctx.stop();
                            }
                        }
                    }
                    Err(e) => {
                        error!("fetch UserSubjectTree error: {}", e);
                        ctx.stop();
                    }
                }
                fut::ok(())
            })
        )
    }
}

impl Handler<ReloadPermissions> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, _msg: ReloadPermissions, ctx: &mut Self::Context) -> Self::Result {
        let subjects = self.permissions.get_subscribe()
            .iter()
            .map(|x| if x.ends_with(REMOVED_SUFFIX) {
                String::from(&x[..(x.len() - REMOVED_SUFFIX.len())])
            } else { x.clone() })
            .chain(MUST_INCLUDE_SUBJECT
                .iter()
                .map(|x| String::from(*x))
            )
            .collect::<HashSet<_>>();
        let app_data = self.app_data.clone();
        let addr = ctx.address();
        Box::new(async move {
            app_data.subscriber.send(UpdateSubscribe {
                client: addr.recipient(),
                subjects,
            }).await
        }
            .into_actor(self)
            .then(|result, act, ctx| {
                let updated = match result {
                    Ok(updated) => updated,
                    Err(e) => {
                        error!("send UpdateSubscribe to main error: {}", e);
                        ctx.stop();
                        return fut::ok(());
                    }
                };
                if !updated {
                    info!("ReloadPermissions do nothing");
                    return fut::ok(());
                }
                if let Err(e) = ctx.address().try_send::<ClientPushMessage>(PermissionUpdatedMessage {
                    permissions: act.permissions.get().into_iter().collect(),
                    claims: act.claims.clone(),
                }.into()) {
                    error!("send ClientPushMessage::SubjectsMessage to self error: {}", e);
                    ctx.stop();
                    return fut::ok(());
                }
                if let Some(ref handle) = act.expire_timer {
                    ctx.cancel_future(handle.clone());
                    act.expire_timer = None;
                }
                if let Some(Claims { ref expires_at, .. }) = act.claims {
                    act.expire_timer = Some(ctx.run_later(
                        (expires_at.clone() - Utc::now()).to_std().unwrap(),
                        |_act, ctx| {
                            ctx.stop()
                        }
                    ))
                }
                fut::ok(())
            })
        )
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for ClientSubscriber {
    fn handle(
        &mut self,
        msg: Result<ws::Message, ws::ProtocolError>,
        ctx: &mut Self::Context,
    ) {
        let msg = match msg {
            Ok(msg) => msg,
            Err(_) => {
                ctx.stop();
                return;
            }
        };
        match msg {
            ws::Message::Ping(msg) => {
                self.last_heartbeat = Utc::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.last_heartbeat = Utc::now();
            }
            ws::Message::Text(text) => {
                if let Ok(msg) = serde_json::from_str::<ClientRequestMessage>(&text) {
                    if let Err(e) = ctx.address().try_send(msg) {
                        error!("send ClientRequestMessage error: {}", e);
                    }
                } else {
                    warn!("ClientRequestMessage deserialize failed");
                }
            }
            ws::Message::Close(_)
            | ws::Message::Continuation(_) => { ctx.stop(); }
            ws::Message::Nop
            | ws::Message::Binary(_) => (),
        }
    }
}

impl Handler<ClientRequestMessage> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, msg: ClientRequestMessage, _ctx: &mut Self::Context) -> Self::Result {
        let request_id = msg.request_id;
        Box::new(async {}
            .into_actor(self)
            .then(move |_, act, ctx| {
                match msg.message {
                    InnerClientRequestMessage::UpdateToken(update_token) =>
                        ctx.address().send(update_token).into_actor(act)
                            .map(|x, _, _| x.map(|x| InnerClientResponseMessage::from(x.unwrap()))),
                }
            })
            .then(move |x, _act, ctx| {
                let response = ClientResponseMessage {
                    request_id,
                    message: match x {
                        Ok(x) => x,
                        Err(e) => {
                            error!("deliver ClientRequestMessage error: {}", e);
                            InnerClientResponseMessage::DeliverMessageFailed
                        },
                    },
                };
                if let Err(e) = ctx.address().try_send::<ClientPushMessage>(response.into()) {
                    error!("send ClientPushMessage::ClientRequestMessage to self error: {}", e);
                }
                fut::ok(())
            })
        )
    }
}

impl Handler<UpdateTokenRequest> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<UpdateTokenResponse, Infallible>>;

    fn handle(&mut self, msg: UpdateTokenRequest, _ctx: &mut Self::Context) -> Self::Result {
        let app_data = self.app_data.clone();
        Box::new(async move {
            match msg.jwt {
                Some(token) => {
                    let claims = app_data.query.token
                        .verify_token(&*app_data.db.read().await, &token)
                        .await?;
                    app_data.query.token
                        .check_token_revoked(&*app_data.db.read().await, claims.jti)
                        .await?;
                    app_data.query.user
                        .check_user_valid_by_id(&*app_data.db.read().await, claims.uid)
                        .await?;
                    Ok(Some(Claims {
                        user_id: claims.uid,
                        jwt_id: claims.jti,
                        expires_at: DateTime::from_utc(NaiveDateTime::from_timestamp(claims.exp, 0), Utc),
                    }))
                },
                None => Ok(None)
            }
        }
            .into_actor(self)
            .then(|claims: Result<_, QueryError>, act, ctx| {
                fut::ok(UpdateTokenResponse {
                    status: match claims {
                        Ok(claims) => {
                            act.claims = claims;
                            match ctx.address().try_send(FullyReloadPermissions) {
                                Ok(_) => UpdateTokenResponseStatus::Ok,
                                Err(e) => {
                                    error!("UpdateToken FullyReloadSubjectsAndClaims error: {}", e);
                                    ctx.stop();
                                    UpdateTokenResponseStatus::InternalError
                                }
                            }
                        }
                        Err(e) => match e {
                            QueryError::InvalidToken { error } =>
                                UpdateTokenResponseStatus::InvalidToken { error },
                            QueryError::TokenNotFound =>
                                UpdateTokenResponseStatus::TokenRevoked,
                            QueryError::UserNotFound =>
                                UpdateTokenResponseStatus::InvalidUser,
                            QueryError::UserBlocked =>
                                UpdateTokenResponseStatus::UserBlocked,
                            e => {
                                error!("verify token error: {}", e);
                                UpdateTokenResponseStatus::InternalError
                            }
                        }
                    }
                })
            })
        )
    }
}
