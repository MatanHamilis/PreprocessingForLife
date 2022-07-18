use log::error;
use std::sync::mpsc::{channel, Receiver, Sender};

pub trait Communicator<S: Default + Copy> {
    fn send(&mut self, obj: &S) -> Option<()>;
    fn receive(&mut self) -> Option<S>;
    fn exchange(&mut self, obj: &S) -> Option<S>;
}

pub struct LocalCommunicator<S: Default> {
    is_first: bool,
    sender: Sender<S>,
    receiver: Receiver<S>,
}

impl<S: Default + Copy> LocalCommunicator<S> {
    fn new_pair() -> (Self, Self) {
        let (sender_1, receiver_1) = channel();
        let (sender_2, receiver_2) = channel();
        (
            LocalCommunicator {
                is_first: false,
                sender: sender_1,
                receiver: receiver_2,
            },
            LocalCommunicator {
                is_first: true,
                sender: sender_2,
                receiver: receiver_1,
            },
        )
    }
}

impl<S: Default + Copy> Communicator<S> for LocalCommunicator<S> {
    fn receive(&mut self) -> Option<S> {
        match self.receiver.recv() {
            Ok(v) => Some(v),
            Err(e) => {
                error!("Receiver error: {}", e);
                None
            }
        }
    }

    fn send(&mut self, obj: &S) -> Option<()> {
        match self.sender.send(*obj) {
            Ok(()) => Some(()),
            Err(e) => {
                error!("Sender error: {}", e);
                None
            }
        }
    }

    fn exchange(&mut self, obj: &S) -> Option<S> {
        if self.is_first {
            self.send(obj);
            self.receive()
        } else {
            let s = self.receive();
            self.send(obj);
            s
        }
    }
}
