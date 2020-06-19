use crate::{
    actors::{
        client_subscriber::ClientSubscriber,
        messages::AnyMessage,
    },
};
use actix::{Addr, Actor, Message, Handler, Context, AsyncContext, WrapFuture};
use log::{error, debug};
use redis::{
    aio::{PubSub, Connection},
    Msg,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::{
    stream::StreamExt,
    sync::RwLock,
};

#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe {
    client: Addr<ClientSubscriber>,
    subject: HashSet<String>,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct RedisMessage(Msg);

pub struct ServerSubscriber {
    publisher: Arc<RwLock<Connection>>,
    subscriber: Arc<RwLock<PubSub>>,
    subject2client: HashMap<String, HashSet<Addr<ClientSubscriber>>>,
    client2subject: HashMap<Addr<ClientSubscriber>, HashSet<String>>,
}

impl ServerSubscriber {
    pub fn new(publisher: Connection, subscriber: PubSub) -> Self {
        Self {
            publisher: Arc::new(RwLock::new(publisher)),
            subscriber: Arc::new(RwLock::new(subscriber)),
            subject2client: HashMap::new(),
            client2subject: HashMap::new(),
        }
    }
}

impl Actor for ServerSubscriber {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        let redis = self.subscriber.clone();
        let addr = ctx.address();
        ctx.spawn(async move {
            let mut redis_mut = redis.write().await;
            if let Err(e) = redis_mut.subscribe(crate::constants::CHANNEL_NAME).await {
                error!("{:?}", e);
                return;
            }
            let mut stream = redis_mut.on_message();
            while let Some(msg) = stream.next().await {
                addr.do_send(RedisMessage(msg));
            }
        }.into_actor(self));
    }
}

impl Handler<RedisMessage> for ServerSubscriber {
    type Result = ();

    fn handle(&mut self, msg: RedisMessage, _ctx: &mut Context<Self>) -> Self::Result {
        let msg: serde_json::Value = match serde_json::from_slice(msg.0.get_payload_bytes()) {
            Ok(r) => r,
            Err(e) => {
                error!("server failed to decode message into value {}", e);
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
            Some(r) => r,
            None => {
                error!("server failed to fetch subject of message");
                return;
            }
        };
        let msg: AnyMessage = match serde_json::from_value(msg) {
            Ok(r) => r,
            Err(e) => {
                error!("server failed to decode value into object {}", e);
                return;
            }
        };
        debug!("receive message of subject \"{}\"", subject);
        if let Some(clients) = self.subject2client.get(&subject) {
            for client in clients {
                client.do_send(msg.clone())
            }
        }
    }
}

impl Handler<Subscribe> for ServerSubscriber {
    type Result = ();

    fn handle(&mut self, msg: Subscribe, _ctx: &mut Context<Self>) -> Self::Result {
        let empty_subjects = HashSet::new();
        let old_subjects = self.client2subject.get(&msg.client)
            .unwrap_or(&empty_subjects);
        // Remove old
        let to_remove = old_subjects - &msg.subject;
        for subject in to_remove.iter() {
            let clients = self.subject2client.get_mut(subject).unwrap();
            clients.remove(&msg.client);
            if clients.is_empty() {
                self.subject2client.remove(subject);
            }
        }
        let to_add = &msg.subject - old_subjects;
        for subject in to_add.iter() {
            let clients = self.subject2client.entry(subject.clone())
                .or_insert_with(|| HashSet::new());
            clients.insert(msg.client.clone());
        }
        if msg.subject.is_empty() {
            self.client2subject.remove(&msg.client);
        } else {
            self.client2subject.insert(msg.client, msg.subject);
        }
    }
}

impl Handler<AnyMessage> for ServerSubscriber {
    type Result = ();

    fn handle(&mut self, msg: AnyMessage, ctx: &mut Self::Context) -> Self::Result {
        let msg = match serde_json::to_string(&msg) {
            Ok(s) => s,
            Err(e) => {
                error!("server failed to encode message {}", e);
                return;
            }
        };
        let redis = self.publisher.clone();
        ctx.spawn(async move {
            let mut redis_mut = redis.write().await;
            if let Err(e) = redis::cmd("PUBLISH").arg(&[crate::constants::CHANNEL_NAME, &msg])
                .query_async::<Connection, ()>(&mut *redis_mut).await {
                error!("server failed to send message {}", e);
            }
        }.into_actor(self));
    }
}