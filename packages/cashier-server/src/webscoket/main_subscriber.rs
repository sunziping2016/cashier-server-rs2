use crate::{
    webscoket::push_messages::PushMessage,
};
use actix::{
    Actor, Message, Handler, Context, AsyncContext,
    WrapFuture, Recipient, ActorContext, ActorFuture, fut,
    ResponseActFuture,
};
use log::{error, debug};
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
#[rtype(result = "()")]
pub struct UpdateSubscribe {
    pub client: Recipient<PushMessage>,
    pub subjects: HashSet<String>,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct RedisMessage(Msg);

pub struct MainSubscriber {
    publisher: Arc<RwLock<Connection>>,
    subscriber: Arc<RwLock<PubSub>>,
    subject2client: HashMap<String, HashSet<Recipient<PushMessage>>>,
    client2subject: HashMap<Recipient<PushMessage>, HashSet<String>>,
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
                if let Err(e) = addr.try_send(RedisMessage(msg)) {
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
    type Result = ();

    fn handle(&mut self, msg: RedisMessage, _ctx: &mut Context<Self>) -> Self::Result {
        let msg: serde_json::Value = match serde_json::from_slice(msg.0.get_payload_bytes()) {
            Ok(r) => r,
            Err(e) => {
                error!("RedisMessage deserialize to value error: {}", e);
                return;
            }
        };
        let subject = msg.get("message")
            .map(|message| message.get("type"))
            .flatten()
            .map(|v| v.as_str())
            .flatten()
            .map(String::from);
        let subject = match subject {
            Some(subject) => subject,
            None => {
                error!("RedisMessage has no subject");
                return;
            }
        };
        let msg: PushMessage = match serde_json::from_value(msg) {
            Ok(msg) => msg,
            Err(e) => {
                error!("RedisMessage deserialize to PushMessage error: {}", e);
                return;
            }
        };
        debug!("receive message: subject \"{}\"", subject);
        if let Some(clients) = self.subject2client.get(&subject) {
            for client in clients {
                if let Err(e) = client.try_send(msg.clone()) {
                    error!("send PushMessage to client error {}", e);
                }
            }
        }
    }
}

impl Handler<UpdateSubscribe> for MainSubscriber {
    type Result = ();

    fn handle(&mut self, msg: UpdateSubscribe, _ctx: &mut Context<Self>) -> Self::Result {
        let empty_subjects = HashSet::new();
        let old_subjects = self.client2subject.get(&msg.client)
            .unwrap_or(&empty_subjects);
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
                .or_insert_with(|| HashSet::new());
            clients.insert(msg.client.clone());
        }
        if msg.subjects.is_empty() {
            self.client2subject.remove(&msg.client);
        } else {
            self.client2subject.insert(msg.client, msg.subjects);
        }
        // Debug
        // debug!("subject2client:");
        // for (subject, clients) in self.subject2client.iter() {
        //     debug!("  {}: {}", subject, clients.len());
        // }
        // debug!("client2subject:");
        // for (i, (_client, subjects)) in self.client2subject.iter().enumerate() {
        //     debug!("  {:?}: {}", i, subjects.iter()
        //         .map(|x| &x[..])
        //         .collect::<Vec<_>>()
        //         .join(", "));
        // }
    }
}

impl Handler<PushMessage> for MainSubscriber {
    type Result = ResponseActFuture<Self, Result<(), Infallible>>;

    fn handle(&mut self, msg: PushMessage, _ctx: &mut Self::Context) -> Self::Result {
        let redis = self.publisher.clone();
        Box::new(async move {
            let msg = match serde_json::to_string(&msg) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("PushMessage serialize error: {}", e);
                    return Ok(());
                }
            };
            let mut redis_mut = redis.write().await;
            if let Err(e) = redis::cmd("PUBLISH").arg(&[crate::constants::CHANNEL_NAME, &msg])
                .query_async::<Connection, ()>(&mut *redis_mut).await {
                error!("send PushMessage to redis error {}", e);
            }
            Ok(())
        }.into_actor(self))
    }
}