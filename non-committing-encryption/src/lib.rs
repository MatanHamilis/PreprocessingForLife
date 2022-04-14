//! # Non Committing Encrytpion
//! This is based on the very basic non-committing encryption scheme from [[CO15]](https://eprint.iacr.org/2015/267.pdf)

pub trait NonCommittingKey<const KEY_SIZE: usize> {
    fn encrypt<const MSG_SIZE: usize>(&self, msg: [u8; MSG_SIZE]) -> [u8; KEY_SIZE];
    fn decrypt<const MSG_SIZE: usize>(&self, ciphertext: [u8; KEY_SIZE]) -> Option<[u8; MSG_SIZE]>;
}
pub type COSchemeKey<const KEY_SIZE: usize> = [u8; KEY_SIZE];

impl<const KEY_SIZE: usize> NonCommittingKey<KEY_SIZE> for COSchemeKey<KEY_SIZE> {
    fn encrypt<const MSG_SIZE: usize>(&self, msg: [u8; MSG_SIZE]) -> [u8; KEY_SIZE] {
        assert!(MSG_SIZE <= KEY_SIZE);
        let mut output = self.clone();
        msg.iter()
            .enumerate()
            .for_each(|(i, msg_i)| output[i] ^= msg_i);
        output
    }

    fn decrypt<const MSG_SIZE: usize>(&self, ciphertext: [u8; KEY_SIZE]) -> Option<[u8; MSG_SIZE]> {
        if self[MSG_SIZE..] != ciphertext[MSG_SIZE..] {
            return None;
        }
        let mut msg: [u8; MSG_SIZE] = [0; MSG_SIZE];
        ciphertext
            .iter()
            .zip(self)
            .take(MSG_SIZE)
            .enumerate()
            .for_each(|(i, (ciphertext_i, key_i))| msg[i] = ciphertext_i ^ key_i);
        Some(msg)
    }
}
#[cfg(test)]
mod tests {
    use crate::COSchemeKey;
    use crate::NonCommittingKey;

    #[test]
    fn check_round_trip_works() {
        let key: COSchemeKey<10> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let msg = [5, 6, 7, 8];
        let cipher_text = key.encrypt(msg);
        assert_eq!(key.decrypt(cipher_text).unwrap(), msg);
    }

    #[test]
    fn check_encryption_fails() {
        let key: COSchemeKey<10> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let msg = [5, 6, 7, 8];
        let mut cipher_text = key.encrypt(msg);
        cipher_text[8] -= 1;
        assert!(key.decrypt::<4>(cipher_text).is_none());
    }
}
