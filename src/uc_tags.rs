use blake3::Hash;
use serde::Serialize;

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct UCTag {
    tag: Hash,
}

impl UCTag {
    pub fn derive(&self, subtag: &impl Serialize) -> Self {
        let subtag = bincode::serialize(subtag).expect("Failed to serialize, unexpected bug");
        Self {
            tag: blake3::keyed_hash(self.tag.as_bytes(), &subtag),
        }
    }
}

impl<T: Serialize> From<T> for UCTag {
    fn from(value: T) -> Self {
        let subtag = bincode::serialize(&value).expect("Failed to serialize, unexpected bug");
        Self {
            tag: blake3::hash(&subtag),
        }
    }
}
