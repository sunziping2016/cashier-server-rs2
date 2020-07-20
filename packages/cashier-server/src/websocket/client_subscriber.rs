use crate::{
    websocket::{
        main_subscriber::UpdateSubscribe,
        push_messages::{
            PermissionIdSubjectAction,
            InternalMessage, PublicMessage,
            InnerInternalMessage, InnerPublicMessage,
            UserRoleCreated, RolePermissionCreated,
        },
    },
    constants::{
        WEBSOCKET_HEARTBEAT_INTERVAL,
        WEBSOCKET_CLIENT_TIMEOUT,
        WEBSOCKET_PERMISSION_REFRESH_INTERVAL,
    },
    queries::{
        users::{PermissionTree, PermissionSubjectAction},
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
use std::{
    fmt,
    collections::HashSet,
    result::Result,
    convert::{Infallible, identity},
    borrow::Cow,
};
use crate::api::app_state::{AppSubscriber, AppDatabase};

const MUST_INCLUDE_SUBJECT: &[&str] = &[
    "user-updated", // for block
    "user-deleted",
    "token-revoked",
    "user-role-updated",
    "role-permission-updated",
];

const REMOVED_SUFFIX: &str = "-self";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PermissionUpdatedMessage {
    permissions: Vec<PermissionIdSubjectAction>,
    available_subjects: Vec<String>,
    claims: Option<Claims>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SubjectUpdatedMessage {
    subjects: Vec<String>
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
#[serde(tag = "status")]
#[serde(rename_all = "kebab-case")]
enum UpdateSubjectResponseStatus {
    Ok,
    DisallowedExtraSubject {
        extra: Vec<String>
    },
    InternalError,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateTokenResponse {
    status: UpdateTokenResponseStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateSubjectResponse {
    status: UpdateSubjectResponseStatus,
}

#[derive(Debug, Serialize, Deserialize, From, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
enum InnerClientResponseMessage {
    UpdateToken(UpdateTokenResponse),
    UpdateSubject(UpdateSubjectResponse),
    DeliverFailed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ClientResponseMessage {
    request_id: u32,
    message: InnerClientResponseMessage,
}

#[derive(Debug, Serialize, Deserialize, From, Message, Clone)]
#[rtype(result = "Result<(), Infallible>")]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
enum ClientPushMessage {
    Push(PublicMessage),
    PermissionUpdated(PermissionUpdatedMessage),
    SubjectUpdated(SubjectUpdatedMessage),
    Response(ClientResponseMessage),
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "Result<UpdateTokenResponse, Infallible>")]
#[serde(rename_all = "camelCase")]
struct UpdateTokenRequest {
    jwt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "Result<UpdateSubjectResponse, Infallible>")]
#[serde(rename_all = "camelCase")]
struct UpdateSubjectRequest {
    subjects: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, From, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
enum InnerClientRequestMessage {
    UpdateToken(UpdateTokenRequest),
    UpdateSubject(UpdateSubjectRequest),
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
pub struct ReloadPermissionsFromDatabase {
    force: bool,
}

#[derive(Message)]
#[rtype(result = "Result<(), Infallible>")]
pub struct ReloadPermissions {
    new_permissions: PermissionTree,
    force: bool,
}

#[derive(Message)]
#[rtype(result = "Result<(), Infallible>")]
pub struct ReloadSubjects {
    new_subjects: HashSet<String>,
    force: bool,
}

pub struct ClientSubscriber {
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    claims: Option<Claims>,
    last_heartbeat: DateTime<Utc>,
    expire_timer: Option<SpawnHandle>,
    permissions: PermissionTree,
    available_subjects: HashSet<String>,
    subjects: HashSet<String>,
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
    pub fn new(
        database: web::Data<AppDatabase>,
        subscriber: web::Data<AppSubscriber>,
    ) -> Self {
        Self {
            database,
            subscriber,
            claims: None,
            last_heartbeat: Utc::now(),
            expire_timer: None,
            permissions: PermissionTree::default(),
            available_subjects: HashSet::new(),
            subjects: HashSet::new(),
        }
    }
    pub fn has_subject(&self, subject: &str) -> bool {
        self.subjects.contains(subject)
    }
    pub fn is_user(&self, uid: i32) -> bool {
        self.claims.as_ref().map(|x| x.user_id == uid).contains(&true)
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
        ctx.run_interval(permission_refresh_interval, move |act, ctx| {
            ctx.spawn(ctx.address().send(ReloadPermissionsFromDatabase {
                force: false,
            })
                .into_actor(act)
                .then(|result, _, ctx| {
                    if let Err(e) = result {
                        error!("refresh ReloadPermissionsFromDatabase error: {}", e);
                        ctx.stop();
                    }
                    fut::ready(())
                })
            );
        });
        ctx.spawn(ctx.address().send(ReloadPermissionsFromDatabase {
            force: true,
        })
            .into_actor(self)
            .then(|result, _, ctx| {
                if let Err(e) = result {
                    error!("initial ReloadPermissionsFromDatabase error: {}", e);
                    ctx.stop();
                }
                fut::ready(())
            })
        );
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        ctx.spawn(self.subscriber.subscriber.send(UpdateSubscribe {
            client: ctx.address().recipient(),
            subjects: HashSet::new(),
        })
            .into_actor(self)
            .then(|result, _, _| {
                if let Err(e) = result {
                    error!("stopping error: {}", e);
                }
                fut::ready(())
            })
        );
        Running::Stop
    }
}

impl Handler<InternalMessage> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, msg: InternalMessage, ctx: &mut Self::Context) -> Self::Result {
        let mut new_permissions: Cow<PermissionTree> = Cow::Borrowed(&self.permissions);
        let (push_message, shutdown_connection):
            (Vec<Option<InnerPublicMessage>>, Vec<bool>) = msg.messages.into_iter()
            .map(|msg| {
                match msg {
                    InnerInternalMessage::TokenAcquired(msg) =>
                        (if self.has_subject("token-acquired") ||
                            (self.has_subject("token-acquired-self") && self.is_user(msg.0.user)) {
                            Some(msg.into())
                        } else { None }, false),
                    InnerInternalMessage::TokenRevoked(msg) => {
                        let uid = msg.uid;
                        (
                            if self.has_subject("token-revoked") ||
                                (self.has_subject("token-revoked-self") && self.is_user(uid)) {
                                Some(msg.into())
                            } else { None },
                            self.is_user(uid),
                        )
                    }
                    InnerInternalMessage::UserCreated(msg) =>
                        (if self.has_subject("user-created") { Some(msg.into()) } else { None },
                         false),
                    InnerInternalMessage::UserUpdated(msg) => {
                        let uid = msg.id;
                        let blocked = msg.blocked.flatten().contains(&true);
                        (
                            if self.has_subject("user-updated") ||
                                (self.has_subject("user-updated-self") && self.is_user(uid)) {
                                Some(msg.into())
                            } else { None },
                            self.is_user(uid) && blocked,
                        )
                    }
                    InnerInternalMessage::UserDeleted(msg) => {
                        let uid = msg.id;
                        (
                            if self.has_subject("user-deleted") ||
                                (self.has_subject("user-deleted-self") && self.is_user(uid)) {
                                Some(msg.into())
                            } else { None },
                            self.is_user(uid),
                        )
                    }
                    InnerInternalMessage::UserRoleCreated(msg) => {
                        if self.is_user(msg.user) {
                            new_permissions.to_mut().add_role(msg.role, msg.role_permissions
                                .into_iter()
                                .map(|x| (x.id, PermissionSubjectAction {
                                    subject: x.subject,
                                    action: x.action,
                                }))
                                .collect()
                            );
                        }
                        (if self.has_subject("user-role-updated") { Some(UserRoleCreated {
                            user: msg.user,
                            role: msg.role,
                        }.into()) } else { None }, false)
                    }
                    InnerInternalMessage::UserRoleDeleted(msg) => {
                        if self.is_user(msg.user) {
                            new_permissions.to_mut().remove_role(msg.role);
                        }
                        (if self.has_subject("user-role-updated") {
                            Some(msg.into())
                        } else { None }, false)
                    }
                    InnerInternalMessage::RolePermissionCreated(msg) => {
                        new_permissions.to_mut().add_permission(msg.role, msg.permission,
                                                                msg.subject, msg.action);
                        (if self.has_subject("role-permission-updated") { Some(RolePermissionCreated {
                            role: msg.role,
                            permission: msg.permission,
                        }.into()) } else { None }, false)
                    }
                    InnerInternalMessage::RolePermissionDeleted(msg) => {
                        new_permissions.to_mut().remove_permission(msg.role, msg.permission);
                        (if self.has_subject("role-permission-updated") {
                            Some(msg.into())
                        } else { None }, false)
                    }
                }
            })
            .unzip();
        let push_message: Vec<_> = push_message.into_iter()
            .filter_map(identity)
            .collect();
        let shutdown_connection = shutdown_connection.into_iter()
            .any(identity);
        let new_permissions = match new_permissions {
            Cow::Owned(new_permissions) => Some(new_permissions),
            Cow::Borrowed(_) => None
        };
        Box::new(if !push_message.is_empty() {
            fut::Either::Left(ctx.address().send::<ClientPushMessage>(PublicMessage {
                sender_uid: msg.sender_uid,
                sender_jti: msg.sender_jti,
                messages: push_message,
                created_at: msg.created_at,
            }.into()).into_actor(self))
        } else {
            fut::Either::Right(fut::ok(Ok(())))
        }
            .then(move |result, act, ctx| {
                if let Err(e) = result {
                    error!("send ClientPushMessage::PublicMessage to self error: {}", e)
                }
                match new_permissions {
                    Some(new_permissions) =>
                        fut::Either::Left(ctx.address().send(ReloadPermissions {
                            new_permissions,
                            force: false,
                        }).into_actor(act)),
                    None => fut::Either::Right(fut::ok(Ok(()))),
                }
                    .then(move |result, _act, ctx| {
                        if let Err(e) = result {
                            error!("send ReloadPermissions to self error: {}", e);
                            ctx.stop();
                        } else if shutdown_connection {
                            ctx.stop();
                        }
                        fut::ok(())
                    })
            })
        )
    }
}

impl Handler<ClientPushMessage> for ClientSubscriber {
    type Result = Result<(), Infallible>;

    fn handle(&mut self, msg: ClientPushMessage, ctx: &mut Self::Context) -> Self::Result {
        match serde_json::to_string(&msg) {
            Ok(msg) => ctx.text(msg),
            Err(e) => error!("serialize ClientPushMessage error: {}", e),
        }
        Ok(())
    }
}

impl Handler<ReloadPermissionsFromDatabase> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, msg: ReloadPermissionsFromDatabase, _ctx: &mut Self::Context) -> Self::Result {
        let database = self.database.clone();
        let user_id = self.claims.as_ref().map(|x| x.user_id);
        Box::new(async move {
            database.query.user
                .fetch_permission_tree(&*database.db.read().await, user_id)
                .await
        }
            .into_actor(self)
            .then(move |permissions, act, ctx| {
                match permissions {
                    Ok(permissions) => {
                        fut::Either::Left(ctx.address().send(ReloadPermissions {
                            new_permissions: permissions,
                            force: msg.force
                        })
                            .into_actor(act)
                            .then(|result, _, ctx| {
                                if let Err(e) = result {
                                    error!("send ReloadPermissions from database to self error: {}", e);
                                    ctx.stop();
                                }
                                fut::ok(())
                            })
                        )
                    }
                    Err(e) => {
                        error!("fetch PermissionTree error: {}", e);
                        ctx.stop();
                        fut::Either::Right(fut::ok(()))
                    }
                }
            })
        )
    }
}

impl Handler<ReloadPermissions> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, msg: ReloadPermissions, ctx: &mut Self::Context) -> Self::Result {
        let force = msg.force;
        if !force && self.permissions == msg.new_permissions {
            return Box::new(fut::ok(()));
        }
        self.permissions = msg.new_permissions;
        self.available_subjects = self.permissions.get_subscribe();
        Box::new(ctx.address().send::<ClientPushMessage>(PermissionUpdatedMessage {
            permissions: self.permissions.get().into_iter()
                .map(|(k, v)| PermissionIdSubjectAction {
                    id: k,
                    subject: v.subject,
                    action: v.action,
                })
                .collect(),
            available_subjects: self.available_subjects.iter()
                .map(String::clone)
                .collect(),
            claims: self.claims.clone(),
        }.into())
            .into_actor(self)
            .then(move |result, act, ctx| {
                if let Err(e) = result {
                    error!("send ClientPushMessage::PermissionUpdatedMessage to self error: {}", e);
                    ctx.stop();
                    fut::Either::Left(fut::ok(()))
                } else {
                    let new_subjects = act.subjects
                        .intersection(&act.available_subjects)
                        .map(String::clone)
                        .collect();
                    fut::Either::Right(ctx.address().send(ReloadSubjects {
                        new_subjects,
                        force,
                    })
                        .into_actor(act)
                        .then(|result, _, ctx| {
                            if let Err(e) = result {
                                error!("send ReloadSubjects to self error: {}", e);
                                ctx.stop();
                            }
                            fut::ok(())
                        })
                    )
                }
            })
        )
    }
}

impl Handler<ReloadSubjects> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, msg: ReloadSubjects, ctx: &mut Self::Context) -> Self::Result {
        if !msg.force && self.subjects == msg.new_subjects {
            return Box::new(fut::ok(()));
        }
        let subjects = msg.new_subjects.iter()
            .map(|x| if x.ends_with(REMOVED_SUFFIX) {
                String::from(&x[..(x.len() - REMOVED_SUFFIX.len())])
            } else { x.clone() })
            .chain(MUST_INCLUDE_SUBJECT
                .iter()
                .map(|x| String::from(*x))
            )
            .collect::<HashSet<_>>();
        Box::new(self.subscriber.subscriber.send(UpdateSubscribe {
            client: ctx.address().recipient(),
            subjects,
        })
            .into_actor(self)
            .then(|result, act, ctx| {
                if let Err(e) = result {
                    error!("send UpdateSubscribe to main error: {}", e);
                    ctx.stop();
                }
                act.subjects = msg.new_subjects;
                ctx.address().send::<ClientPushMessage>(SubjectUpdatedMessage {
                    subjects: act.subjects.iter().map(String::clone).collect(),
                }.into())
                    .into_actor(act)
                    .then(|result, _, ctx| {
                        if let Err(e) = result {
                            error!("send ClientPushMessage::SubjectUpdatedMessage to self error: {}", e);
                            ctx.stop();
                        }
                        fut::ok(())
                    })
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
                match serde_json::from_str::<ClientRequestMessage>(&text) {
                    Ok(msg) => {
                        ctx.spawn(ctx.address().send(msg)
                            .into_actor(self)
                            .then(|result, _, _| {
                                if let Err(e) = result {
                                    error!("send ClientRequestMessage error: {}", e);
                                }
                                fut::ready(())
                            })
                        );
                    }
                    Err(e) =>
                        warn!("deserialize ClientRequestMessage error: {}", e),
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
                let addr = ctx.address();
                async move {
                    match msg.message {
                        InnerClientRequestMessage::UpdateToken(update_token) =>
                            addr.send(update_token).await
                                .map(|x| InnerClientResponseMessage::from(x.unwrap())),
                        InnerClientRequestMessage::UpdateSubject(update_subject) =>
                            addr.send(update_subject).await
                                .map(|x| InnerClientResponseMessage::from(x.unwrap())),
                    }
                }.into_actor(act)
            })
            .then(move |x, act, ctx| {
                let response = ClientResponseMessage {
                    request_id,
                    message: match x {
                        Ok(x) => x,
                        Err(e) => {
                            error!("deliver ClientRequestMessage error: {}", e);
                            InnerClientResponseMessage::DeliverFailed
                        },
                    },
                };
                ctx.address().send::<ClientPushMessage>(response.into())
                    .into_actor(act)
                    .then(|result, _, _| {
                        if let Err(e) = result {
                            error!("send ClientPushMessage::ClientResponseMessage to self error: {}", e);
                        }
                        fut::ok(())
                    })
            })
        )
    }
}

impl Handler<UpdateTokenRequest> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<UpdateTokenResponse, Infallible>>;

    fn handle(&mut self, msg: UpdateTokenRequest, _ctx: &mut Self::Context) -> Self::Result {
        let database = self.database.clone();
        Box::new(async move {
            match msg.jwt {
                Some(token) => {
                    let claims = database.query.token
                        .verify_token(&*database.db.read().await, &token)
                        .await?;
                    database.query.token
                        .check_token_revoked(&*database.db.read().await, claims.jti)
                        .await?;
                    database.query.user
                        .check_user_valid_by_id(&*database.db.read().await, claims.uid)
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
                match claims {
                    Ok(claims) => {
                        act.claims = claims;
                        if let Some(ref handle) = act.expire_timer {
                            ctx.cancel_future(*handle);
                            act.expire_timer = None;
                        }
                        if let Some(Claims { ref expires_at, .. }) = act.claims {
                            act.expire_timer = Some(ctx.run_later(
                                (*expires_at - Utc::now()).to_std().unwrap(),
                                |_act, ctx| {
                                    ctx.stop()
                                }
                            ))
                        }
                        fut::Either::Left(ctx.address().send(ReloadPermissionsFromDatabase {
                            force: false,
                        })
                            .into_actor(act)
                            .then(|result, _, ctx| {
                                fut::ok(UpdateTokenResponse {
                                    status: match result {
                                        Ok(_) => UpdateTokenResponseStatus::Ok,
                                        Err(e) => {
                                            error!("UpdateTokenRequest ReloadPermissions error: {}", e);
                                            ctx.stop();
                                            UpdateTokenResponseStatus::InternalError
                                        }
                                    }
                                })
                            })
                        )
                    }
                    Err(e) => fut::Either::Right(fut::ok(UpdateTokenResponse {
                        status: match e {
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
                    }))
                }
            })
        )
    }
}

impl Handler<UpdateSubjectRequest> for ClientSubscriber {
    type Result = ResponseActFuture<Self, Result<UpdateSubjectResponse, Infallible>>;

    fn handle(&mut self, msg: UpdateSubjectRequest, _ctx: &mut Self::Context) -> Self::Result {
        let request_subjects = msg.subjects.into_iter().collect::<HashSet<_>>();
        let extra_subjects = request_subjects.difference(&self.available_subjects)
            .map(String::clone)
            .collect::<Vec<_>>();
        Box::new(async {}.into_actor(self)
            .then(move |_, act, ctx| {
                if !extra_subjects.is_empty() {
                    return fut::Either::Left(fut::ok(UpdateSubjectResponse {
                        status: UpdateSubjectResponseStatus::DisallowedExtraSubject {
                            extra: extra_subjects,
                        }
                    }))
                }
                fut::Either::Right(ctx.address().send(ReloadSubjects {
                    new_subjects: request_subjects,
                    force: false,
                })
                    .into_actor(act)
                    .then(|result, _, ctx| {
                        fut::ok(UpdateSubjectResponse {
                            status: match result {
                                Ok(_) => UpdateSubjectResponseStatus::Ok,
                                Err(e) => {
                                    error!("send ReloadSubjects to self for request error: {}", e);
                                    ctx.stop();
                                    UpdateSubjectResponseStatus::InternalError
                                }
                            }
                        })
                    })
                )
            })
        )
    }
}