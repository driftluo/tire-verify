use rlp::DecoderError;

#[derive(Debug)]
pub enum TrieError {
    DB,
    Decoder(DecoderError),
    InvalidData,
    InvalidStateRoot,
    InvalidProof,
}

impl From<DecoderError> for TrieError {
    fn from(error: DecoderError) -> Self {
        TrieError::Decoder(error)
    }
}
