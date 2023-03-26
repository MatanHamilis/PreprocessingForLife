use std::{
    borrow::Borrow,
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use futures::{
    future::try_join_all,
    stream::{select_all, SplitSink, SplitStream},
    SinkExt, StreamExt, TryStreamExt,
};
use tokio::{
    join,
    net::{TcpListener, TcpStream},
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
};
use tokio_tungstenite::{
    accept_async, client_async, connect_async,
    tungstenite::{http::Request, Message},
    MaybeTlsStream, WebSocketStream,
};
use url::Url;

use crate::uc_tags::UCTag;

use super::{
    DownstreamMessage, DownstreamMessageType, MultiPartyEngineImpl, PartyId, UpstreamMessage,
};

struct NetworkRouter {
    local_party_id: PartyId,
    upstream: HashMap<UCTag, UnboundedSender<UpstreamMessage>>,
    downstream: UnboundedReceiver<DownstreamMessage>,
    peers_send: HashMap<PartyId, SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>,
    peers_receive: HashMap<PartyId, SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
    tag: HashMap<PartyId, UCTag>,
    pending: HashMap<UCTag, Vec<UpstreamMessage>>,
}

async fn handle_single_conn(
    stream: MaybeTlsStream<TcpStream>,
) -> Result<(u64, WebSocketStream<MaybeTlsStream<TcpStream>>), ()> {
    let mut conn = accept_async(stream).await.or(Err(()))?;
    let msg = conn.next().await.unwrap().unwrap();
    let party_id: PartyId = bincode::deserialize(&msg.into_data()).or(Err(()))?;
    Ok((party_id, conn))
}
async fn receive_connections(
    port: u16,
    connection_count: usize,
) -> Result<HashMap<PartyId, WebSocketStream<MaybeTlsStream<TcpStream>>>, ()> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port))
        .await
        .unwrap();
    let mut futures = Vec::with_capacity(connection_count);
    for _ in 0..connection_count {
        let (stream, _) = listener.accept().await.unwrap();
        futures.push(handle_single_conn(MaybeTlsStream::Plain(stream)));
    }
    let res = try_join_all(futures).await.or(Err(()))?;
    Ok(res.into_iter().collect())
}

async fn make_connections(
    my_id: PartyId,
    peers: &HashMap<PartyId, SocketAddrV4>,
) -> Result<HashMap<PartyId, WebSocketStream<MaybeTlsStream<TcpStream>>>, ()> {
    const CONNECTION_ATTEMPTS: usize = 10;
    const CONNECTION_ATTEMPTS_SLEEP_MILLIS: u64 = 1000;
    let futures: Vec<_> = peers
        .iter()
        .filter(|(i, _)| *i > &my_id)
        .map(|(party_id, addr)| async move {
            let req = Url::parse(format!("ws://{}/socket", addr.to_string()).as_str()).unwrap();
            let mut iter_idx = 0;
            let (mut conn, _) = loop {
                match connect_async(req.clone()).await {
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(CONNECTION_ATTEMPTS_SLEEP_MILLIS))
                            .await;
                        iter_idx += 1;
                        if iter_idx == CONNECTION_ATTEMPTS {
                            return Err(());
                        }
                    }
                    Ok(v) => break v,
                }
            };
            let msg = Message::Binary(bincode::serialize(&my_id).unwrap());
            conn.send(msg).await.unwrap();
            Ok((*party_id, conn))
        })
        .collect();
    let res = try_join_all(futures).await.or(Err(()))?;
    Ok(res.into_iter().collect())
}
impl NetworkRouter {
    pub async fn new(
        local_party_id: PartyId,
        peers: &HashMap<PartyId, SocketAddrV4>,
        root_tag: UCTag,
        total_party_count: usize,
        listen_port: u16,
    ) -> Option<(Self, MultiPartyEngineImpl)> {
        let parties: Box<[PartyId]> = peers.keys().copied().collect();
        let (downstream_sender, downstream_receiver) = unbounded_channel();

        let engine = MultiPartyEngineImpl::new(
            local_party_id,
            root_tag.clone(),
            downstream_sender,
            Arc::from(parties),
        );

        let expected_incoming_connections =
            peers.iter().filter(|(i, _)| *i < &local_party_id).count();
        let incoming_conns = receive_connections(listen_port, expected_incoming_connections);
        let outgoing_conns = make_connections(local_party_id, peers);
        let (incoming_conns, outgoing_conns) = join!(incoming_conns, outgoing_conns);
        let (incoming_conns, outgoing_conns) = (
            incoming_conns.unwrap(),
            outgoing_conns.expect(
                format!(
                    "Failed to obtain outgoing conns! party_id: {}",
                    local_party_id
                )
                .as_str(),
            ),
        );

        let mut peers_send = HashMap::with_capacity(total_party_count - 1);
        let mut peers_receive = HashMap::with_capacity(total_party_count - 1);

        outgoing_conns
            .into_iter()
            .chain(incoming_conns.into_iter())
            .for_each(|(pid, conn)| {
                let (snd, recv) = conn.split();
                peers_send.insert(pid, snd);
                peers_receive.insert(pid, recv);
            });

        Some((
            Self {
                downstream: downstream_receiver,
                upstream: HashMap::new(),
                local_party_id,
                peers_send,
                peers_receive,
                tag: HashMap::new(),
                pending: HashMap::new(),
            },
            engine,
        ))
    }
    async fn handle_downstream(&mut self, v: Option<DownstreamMessage>) {
        match v {
            Some(DownstreamMessage { from: _, tag, msg }) => match msg {
                DownstreamMessageType::Register(upstream_sender) => {
                    if let Some(v) = self.pending.remove(&tag) {
                        v.into_iter().for_each(|m| {
                            upstream_sender
                                .send(m)
                                .expect("Failed to send upstream, malformed sender.");
                        })
                    }
                    self.upstream
                        .insert(tag, upstream_sender)
                        .ok_or(())
                        .expect_err("Tag already exists, fatal error!");
                }
                DownstreamMessageType::Deregister => {
                    self.upstream
                        .remove(&tag)
                        .expect("Deregistering missing tag!");
                }
                DownstreamMessageType::Data(dest, msg) => {
                    let snd = self
                        .peers_send
                        .get_mut(&dest)
                        .expect("Tried sending to unknown peer, fatal!");
                    let tag_msg = Message::from(&tag.as_ref()[..]);
                    snd.send(tag_msg).await.expect("Failed to send!");
                    let msg: &Box<[u8]> = msg.borrow();
                    let msg: &[u8] = msg.borrow();
                    let msg = Message::from(msg);
                    snd.send(Message::from(msg)).await.expect("Failed to send!");
                }
            },
            None => {
                panic!(); // Local party left, unexpected, should have deregistered first.
            }
        }
    }
    fn handle_upstream(
        &mut self,
        v: Option<Result<(PartyId, Message), (PartyId, tokio_tungstenite::tungstenite::Error)>>,
    ) {
        match v {
            None => {
                panic!();
            }
            Some(v) => {
                let (pid, msg) = match v {
                    Ok(x) => x,
                    Err((pid, _)) => {
                        println!("Got error, my id: {}, peer: {}", self.local_party_id, pid);
                        panic!()
                    }
                };
                match msg {
                    Message::Text(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                        panic!()
                    }
                    Message::Close(_) => {
                        self.peers_send
                            .remove(&pid)
                            .expect("Receive Close message for nonexistant peer!");
                    }
                    Message::Binary(v) => match self.tag.remove(&pid) {
                        None => {
                            let tag: UCTag = bincode::deserialize(&v)
                                .expect("Malformed data - can't decode UCTag");
                            self.tag.insert(pid, tag);
                        }
                        Some(tag) => {
                            let boxed: Box<[u8]> = v.into();
                            let msg = UpstreamMessage {
                                from: pid,
                                content: Arc::from(boxed),
                            };
                            match self.upstream.get_mut(&tag) {
                                None => self.pending.entry(tag).or_default().push(msg),
                                Some(snd) => {
                                    snd.send(msg).expect("Upstream sender closed unexpectedly!")
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    pub async fn launch(mut self) {
        let mut peers_recv = select_all(
            self.peers_receive
                .drain()
                .map(|(pid, recv)| recv.map_ok(move |m| (pid, m)).map_err(move |e| (pid, e))),
        );
        loop {
            let upstream_before = self.upstream.len();
            select! {
                v = self.downstream.recv() => { self.handle_downstream(v).await} // The await here is just for sending on the websocket.
                v = peers_recv.next() => { self.handle_upstream(v) }
            }
            let upstream_after = self.upstream.len(); // We leave only if we have no more clients to serve.
            if upstream_before == 1 && upstream_after == 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, SocketAddrV4},
    };

    use futures::future::try_join_all;

    use crate::{
        engine::{MultiPartyEngine, PartyId},
        uc_tags::UCTag,
    };

    use super::NetworkRouter;

    async fn do_some_mpc(mut engine: impl MultiPartyEngine) -> Result<(), ()> {
        let my_id = engine.my_party_id();
        let parties: Vec<_> = engine
            .party_ids()
            .iter()
            .copied()
            .filter(|i| i != &my_id)
            .collect();
        parties.iter().for_each(|peer_id| {
            engine.send((my_id, peer_id), *peer_id);
        });
        let mut received: Vec<((PartyId, PartyId), PartyId)> = vec![];
        for _ in parties {
            received.push(engine.recv().await.unwrap())
        }
        for p in received {
            assert_eq!(p.0 .0, p.1);
            assert_eq!(p.0 .1, my_id);
        }
        Ok(())
    }
    #[tokio::test]
    async fn test_networked_router() {
        const PARTIES_COUNT: usize = 10;
        const ROOT_TAG: &str = "ROOT TAG";
        let party_ids: [PartyId; PARTIES_COUNT] = core::array::from_fn(|i| (i + 1) as PartyId);
        let addresses = HashMap::from_iter(party_ids.iter().map(|i| {
            (
                *i,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000 + *i as u16),
            )
        }));

        let mut routers = vec![];
        for id in party_ids {
            let personal_peers = addresses.clone();
            routers.push(async move {
                let personal_port = personal_peers.get(&id).unwrap().port();
                NetworkRouter::new(
                    id,
                    &personal_peers,
                    UCTag::new(&ROOT_TAG),
                    PARTIES_COUNT,
                    personal_port,
                )
                .await
                .ok_or(())
            })
        }

        let (routers, engines): (Vec<_>, Vec<_>) =
            try_join_all(routers).await.unwrap().into_iter().unzip();

        // Start routers
        let router_handles: Vec<_> = routers
            .into_iter()
            .map(|r| tokio::spawn(r.launch()))
            .collect();

        let mpc_handles: Vec<_> = engines.into_iter().map(|e| do_some_mpc(e)).collect();
        try_join_all(mpc_handles).await.unwrap();
        try_join_all(router_handles).await.unwrap();
    }
}
