use std::fmt::Display;

use blake3::Hash;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct UCTag(Hash);

impl Display for UCTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.0.as_bytes()))
    }
}

impl UCTag {
    pub fn new(tag: &impl Serialize) -> Self {
        let mut hasher = blake3::Hasher::new();
        bincode::serialize_into(&mut hasher, tag).expect("Tag serialize failed!");
        Self(hasher.finalize())
    }
    pub fn derive(&self, subtag: impl Serialize) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(self.0.as_bytes());
        bincode::serialize_into(&mut hasher, &subtag).expect("Failed to serialize, unexpected bug");
        Self(hasher.finalize())
    }
}

// impl<T: Serialize> From<T> for UCTag {
//     fn from(value: T) -> Self {
//         let subtag = bincode::serialize(&value).expect("Failed to serialize, unexpected bug");
//         Self {
//             tag: blake3::hash(&subtag),
//         }
//     }
// }

impl Serialize for UCTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl From<UCTag> for [u8; 32] {
    fn from(value: UCTag) -> Self {
        value.0.into()
    }
}

impl<'de> Deserialize<'de> for UCTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <[u8; 32] as Deserialize>::deserialize(deserializer)
            .map(Into::into)
            .map(Self)
    }
}

impl AsRef<[u8; 32]> for UCTag {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}
