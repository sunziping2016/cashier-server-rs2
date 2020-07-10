use crate::{
    websocket::push_messages::InternalMessage,
};
use actix::{
    Actor, Message, Handler, Context, AsyncContext,
    WrapFuture, Recipient, ActorContext, ActorFuture, fut,
    ResponseActFuture,
};
use log::{debug, error};
use redis::{
    aio::{PubSub, Connection},
    Msg,
};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    result::Result,
    sync::Arc,
};
use tokio::{
    stream::StreamExt,
    sync::RwLock,
};

#[derive(Message)]
#[rtype(result = "Result<(), Infallible>")]
pub struct UpdateSubscribe {
    pub client: Recipient<InternalMessage>,
    pub subjects: HashSet<String>,
}

#[derive(Message)]
#[rtype(result = "Result<(), Infallible>")]
pub struct RedisMessage(Msg);

pub struct MainSubscriber {
    publisher: Arc<RwLock<Connection>>,
    subscriber: Arc<RwLock<PubSub>>,
    subject2client: HashMap<String, HashSet<Recipient<InternalMessage>>>,
    client2subject: HashMap<Recipient<InternalMessage>, HashSet<String>>,
}

impl MainSubscriber {
    pub fn new(publisher: Connection, subscriber: PubSub) -> Self {
        Self {
            publisher: Arc::new(RwLock::new(publisher)),
            subscriber: Arc::new(RwLock::new(subscriber)),
            subject2client: HashMap::new(),
            client2subject: HashMap::new(),
        }
    }
}

impl Actor for MainSubscriber {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        let redis = self.subscriber.clone();
        let addr = ctx.address();
        ctx.spawn(async move {
            let mut redis_mut = redis.write().await;
            if let Err(e) = redis_mut.subscribe(crate::constants::CHANNEL_NAME).await {
                error!("subscribe redis error: {}", e);
                return;
            }
            let mut stream = redis_mut.on_message();
            while let Some(msg) = stream.next().await {
                if let Err(e) = addr.send(RedisMessage(msg)).await {
                    error!("send RedisMessage error: {}", e);
                }
            }
        }
            .into_actor(self)
            .then(|_, _, ctx| {
                ctx.stop();
                fut::ready(())
            }));
    }
}

impl Handler<RedisMessage> for MainSubscriber {
    type Result = Result<(), Infallible>;

    fn handle(&mut self, msg: RedisMessage, ctx: &mut Context<Self>) -> Self::Result {
        let origin_msg: InternalMessage = match serde_json::from_slice(msg.0.get_payload_bytes()) {
            Ok(r) => r,
            Err(e) => {
                error!("RedisMessage deserialize error: {}", e);
                return Ok(());
            }
        };
        let mut deliver_msgs: HashMap<Recipient<InternalMessage>, InternalMessage> = HashMap::new();
        for msg in origin_msg.messages.iter() {
            let subject = inflector::cases::kebabcase::to_kebab_case(msg.as_ref());
            if let Some(clients) = self.subject2client.get(&subject) {
                for client in clients {
                    let mailbox = &mut deliver_msgs.entry((*client).clone())
                        .or_insert_with(|| InternalMessage {
                            sender_uid: origin_msg.sender_uid,
                            sender_jti: origin_msg.sender_jti,
                            messages: Vec::new(),
                            created_at: origin_msg.created_at,
                        }).messages;
                    mailbox.push(msg.clone())
                }
            }
        }
        for (client, msg) in deliver_msgs.into_iter() {
            ctx.spawn(client.send(msg.clone())
                .into_actor(self)
                .then(|result, _, _| {
                    if let Err(e) = result {
                        error!("send InternalMessage to client error {}", e);
                    }
                    fut::ready(())
                })
            );
        }
        Ok(())
    }
}

impl Handler<UpdateSubscribe> for MainSubscriber {
    type Result = Result<(), Infallible>;

    fn handle(&mut self, msg: UpdateSubscribe, _ctx: &mut Context<Self>) -> Self::Result {
        let empty_subjects = HashSet::new();
        let old_subjects = self.client2subject.get(&msg.client)
            .unwrap_or(&empty_subjects);
        if *old_subjects == msg.subjects {
            return Ok(());
        }
        // Remove old
        let to_remove = old_subjects - &msg.subjects;
        for subject in to_remove.iter() {
            let clients = self.subject2client.get_mut(subject).unwrap();
            clients.remove(&msg.client);
            if clients.is_empty() {
                self.subject2client.remove(subject);
            }
        }
        let to_add = &msg.subjects - old_subjects;
        for subject in to_add.iter() {
            let clients = self.subject2client.entry(subject.clone())
                .or_insert_with(HashSet::new);
            clients.insert(msg.client.clone());
        }
        if msg.subjects.is_empty() {
            self.client2subject.remove(&msg.client);
        } else {
            self.client2subject.insert(msg.client, msg.subjects);
        }
        // Debug
        debug!("subject2client:");
        for (subject, clients) in self.subject2client.iter() {
            debug!("  {}: {}", subject, clients.len());
        }
        debug!("client2subject:");
        for (i, (_client, subjects)) in self.client2subject.iter().enumerate() {
            debug!("  {:?}: {}", i, subjects.iter()
                .map(|x| &x[..])
                .collect::<Vec<_>>()
                .join(", "));
        }
        Ok(())
    }
}

impl Handler<InternalMessage> for MainSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, msg: InternalMessage, _ctx: &mut Self::Context) -> Self::Result {
        let redis = self.publisher.clone();
        Box::new(async move {
            let msg = match serde_json::to_string(&msg) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("InternalMessage serialize error: {}", e);
                    return Ok(());
                }
            };
            let mut redis_mut = redis.write().await;
            if let Err(e) = redis::cmd("PUBLISH").arg(&[crate::constants::CHANNEL_NAME, &msg])
                .query_async::<Connection, ()>(&mut *redis_mut).await {
                error!("send InternalMessage to redis error {}", e);
            }
            Ok(())
        }.into_actor(self))
    }
}