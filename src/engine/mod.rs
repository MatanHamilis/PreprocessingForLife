mod network_router;
pub use network_router::NetworkRouter;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use async_trait::async_trait;
use rand::{rngs::ThreadRng, thread_rng};
use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::uc_tags::UCTag;
pub type PartyId = u64;

#[async_trait]
pub trait MultiPartyEngine: Send + Sync + 'static {
    type Rng: CryptoRng + RngCore;
    fn send(&mut self, msg: impl Serialize, dest: PartyId);
    fn send_multicast(&mut self, msg: impl Serialize, dest: &[PartyId]);
    fn broadcast(&mut self, msg: impl Serialize);
    async fn recv<T: DeserializeOwned>(&mut self) -> Option<(T, PartyId)>;
    async fn recv_from<T: DeserializeOwned>(&mut self, from: PartyId) -> Option<T>;
    fn sub_protocol_with(&self, tag: impl Serialize, parties: Arc<Box<[PartyId]>>) -> Self;
    fn sub_protocol(&self, tag: impl Serialize) -> Self;
    fn my_party_id(&self) -> PartyId;
    fn party_ids(&self) -> &[PartyId];
    fn uc_tag(&self) -> &UCTag;
    fn rng() -> Self::Rng;
}

#[derive(Debug)]
pub enum DownstreamMessageType {
    Register(UnboundedSender<UpstreamMessage>),
    Deregister,
    Data(PartyId, Arc<Box<[u8]>>),
}

#[derive(Debug)]
pub struct DownstreamMessage {
    from: PartyId,
    tag: UCTag,
    msg: DownstreamMessageType,
}

#[derive(Debug)]
pub struct UpstreamMessage {
    from: PartyId,
    content: Arc<Box<[u8]>>,
}

// App code is "upstream", towards peer is "downstream".
pub struct MultiPartyEngineImpl {
    tag: UCTag,
    id: PartyId,
    downstream_sender: UnboundedSender<DownstreamMessage>,
    upstream_receiver: UnboundedReceiver<UpstreamMessage>,
    parties: Arc<Box<[PartyId]>>,
    buffer: VecDeque<UpstreamMessage>,
}

impl MultiPartyEngineImpl {
    pub fn new(
        id: PartyId,
        tag: UCTag,
        downstream_sender: UnboundedSender<DownstreamMessage>,
        parties: Arc<Box<[PartyId]>>,
    ) -> Self {
        let (upstream_sender, upstream_receiver) = unbounded_channel();
        let msg = DownstreamMessage {
            from: id,
            tag,
            msg: DownstreamMessageType::Register(upstream_sender),
        };
        downstream_sender.send(msg).unwrap();
        let output = Self {
            tag,
            id,
            downstream_sender,
            upstream_receiver,
            parties: parties,
            buffer: VecDeque::new(),
        };
        output
    }
}

impl MultiPartyEngineImpl {
    fn send_serialized(&mut self, content: Arc<Box<[u8]>>, dest: PartyId) {
        let msg = DownstreamMessage {
            from: self.id,
            tag: self.tag,
            msg: DownstreamMessageType::Data(dest, content),
        };
        self.downstream_sender
            .send(msg)
            .expect("Failed to send downstream, early router leaving?");
    }
    fn serialize_msg(content: impl Serialize) -> Box<[u8]> {
        bincode::serialize(&content)
            .expect("Serialization failed!")
            .into()
    }
}

#[async_trait]
impl MultiPartyEngine for MultiPartyEngineImpl {
    type Rng = ThreadRng;
    fn uc_tag(&self) -> &UCTag {
        &self.tag
    }
    fn rng() -> Self::Rng {
        thread_rng()
    }
    fn my_party_id(&self) -> PartyId {
        self.id
    }
    fn send(&mut self, msg: impl Serialize, dest: PartyId) {
        let content = Arc::new(Self::serialize_msg(msg));
        self.send_serialized(content, dest);
    }
    fn send_multicast(&mut self, msg: impl Serialize, dest: &[PartyId]) {
        let content = Arc::new(Self::serialize_msg(msg));
        for p in dest {
            self.send_serialized(content.clone(), *p);
        }
    }
    fn broadcast(&mut self, msg: impl Serialize) {
        let content = Arc::new(Self::serialize_msg(msg));
        let my_id = self.my_party_id();
        let parties = self.parties.clone();
        for p in parties.iter().filter(|v| *v != &my_id) {
            self.send_serialized(content.clone(), *p)
        }
    }
    fn party_ids(&self) -> &[PartyId] {
        &self.parties
    }
    fn sub_protocol(&self, tag: impl Serialize) -> Self {
        let engine = Self::new(
            self.id,
            self.tag.derive(tag),
            self.downstream_sender.clone(),
            self.parties.clone(),
        );
        engine
    }
    async fn recv<T: DeserializeOwned>(&mut self) -> Option<(T, PartyId)> {
        let received = if let Some(v) = self.buffer.pop_front() {
            v
        } else {
            self.upstream_receiver.recv().await?
        };
        let val = bincode::deserialize(&received.content).ok()?;
        Some((val, received.from))
    }
    async fn recv_from<T: DeserializeOwned>(&mut self, from: PartyId) -> Option<T> {
        let upstream_msg =
            if let Some((idx, _)) = self.buffer.iter().enumerate().find(|(_, m)| m.from == from) {
                let v = self.buffer.remove(idx).unwrap();
                v
            } else {
                loop {
                    let msg_got = self.upstream_receiver.recv().await?;
                    if msg_got.from == from {
                        break msg_got;
                    } else {
                        self.buffer.push_back(msg_got)
                    }
                }
            };
        let val = bincode::deserialize(&upstream_msg.content).ok()?;
        Some(val)
    }
    fn sub_protocol_with(&self, tag: impl Serialize, parties: Arc<Box<[PartyId]>>) -> Self {
        for p in parties.iter() {
            assert!(self.parties.contains(p));
        }
        Self::new(
            self.id,
            self.tag.derive(tag),
            self.downstream_sender.clone(),
            parties,
        )
    }
}

impl Drop for MultiPartyEngineImpl {
    fn drop(&mut self) {
        let msg = DownstreamMessage {
            from: self.id,
            tag: self.tag,
            msg: DownstreamMessageType::Deregister,
        };
        self.downstream_sender.send(msg).unwrap();
    }
}

pub struct LocalRouter {
    downstream_receiver: UnboundedReceiver<DownstreamMessage>,
    upstream_senders: HashMap<(PartyId, UCTag), UnboundedSender<UpstreamMessage>>,
}

impl LocalRouter {
    pub fn new(
        root_tag: UCTag,
        parties_set: &HashSet<PartyId>,
    ) -> (Self, HashMap<PartyId, impl MultiPartyEngine>) {
        let mut engines = HashMap::new();
        let upstream_senders = HashMap::new();
        let (_downstream_sender, downstream_receiver) = unbounded_channel();
        let parties: Arc<Box<[PartyId]>> =
            Arc::new(Vec::from_iter(parties_set.iter().copied()).into());
        for p in parties_set {
            let instance = MultiPartyEngineImpl::new(
                *p,
                root_tag,
                _downstream_sender.clone(),
                parties.clone(),
            );
            engines.insert(*p, instance);
        }
        let output = Self {
            downstream_receiver,
            upstream_senders,
        };
        (output, engines)
    }
    pub async fn launch(mut self) -> Result<usize, ()> {
        let mut total_bytes = 0;
        let mut pending = HashMap::<(PartyId, UCTag), Vec<UpstreamMessage>>::new();
        loop {
            let DownstreamMessage { from, tag, msg } =
                self.downstream_receiver.recv().await.ok_or(())?;
            match msg {
                DownstreamMessageType::Register(upstream) => {
                    if let Some(v) = pending.remove(&(from, tag)) {
                        v.into_iter().for_each(|item| {
                            upstream.send(item).expect("Channel closed unexpectedly!");
                        });
                    }
                    self.upstream_senders.insert((from, tag), upstream);
                }
                DownstreamMessageType::Deregister => {
                    self.upstream_senders.remove(&(from, tag));
                    if self.upstream_senders.is_empty() {
                        return Ok(total_bytes);
                    }
                }
                DownstreamMessageType::Data(dest, content) => {
                    total_bytes += content.len();
                    let message = UpstreamMessage { from, content };
                    if let Some(v) = self.upstream_senders.get(&(dest, tag)) {
                        v.send(message).unwrap();
                    } else {
                        pending.entry((dest, tag)).or_default().push(message);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::uc_tags::UCTag;

    use super::LocalRouter;
    use super::MultiPartyEngine;
    use super::PartyId;
    use std::collections::HashSet;
    #[tokio::test]
    async fn test_simple() {
        let party_ids = [1u64, 2u64, 3u64];
        let parties_set = HashSet::from_iter(party_ids.iter().copied());
        let (router, mut engines) = LocalRouter::new(UCTag::new(&"root_tag"), &parties_set);
        let router_handle = tokio::spawn(router.launch());
        for p in party_ids.iter() {
            let p_eng = engines.get_mut(p).unwrap();
            for q in party_ids.iter() {
                if p == q {
                    continue;
                }
                p_eng.send(&(*p, *q), *q);
            }
        }
        for p in party_ids.iter() {
            let p_eng = engines.get_mut(p).unwrap();
            for _ in 0..party_ids.len() - 1 {
                let ((from, to), orig): ((PartyId, PartyId), PartyId) = p_eng.recv().await.unwrap();
                assert_eq!(from, orig);
                assert_eq!(to, *p);
            }
        }
        drop(engines);
        router_handle.await.unwrap().unwrap();
    }
}
