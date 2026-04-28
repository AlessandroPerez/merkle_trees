use rs_merkle::Hasher;

#[derive(Clone)]
pub struct Blake3Algorithm;

impl Hasher for Blake3Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}
