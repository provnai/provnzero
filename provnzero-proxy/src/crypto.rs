use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, Serializable,
};
use rand::rngs::OsRng;

// Define HPKE primitives matching the SDK: X25519, HKDF-SHA256, AES-256-GCM
type KemImpl = X25519HkdfSha256;
type AeadImpl = AesGcm256;
type KdfImpl = HkdfSha256;

const PROVN_ZDR_INFO: &[u8] = b"provnzero-v2";

/// Generate a server keypair for HPKE
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (private_key, public_key) = KemImpl::gen_keypair(&mut OsRng);
    (
        private_key.to_bytes().to_vec(),
        public_key.to_bytes().to_vec(),
    )
}

/// Server opens an encapsulated HPKE message
pub fn hpke_open(
    encapsulated_key: &[u8],
    server_privkey: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, hpke::HpkeError> {
    let sk = <KemImpl as Kem>::PrivateKey::from_bytes(server_privkey)
        .map_err(|_| hpke::HpkeError::ValidationError)?;

    let encap = <KemImpl as Kem>::EncappedKey::from_bytes(encapsulated_key)
        .map_err(|_| hpke::HpkeError::ValidationError)?;

    hpke::setup_receiver::<AeadImpl, KdfImpl, KemImpl>(
        &hpke::OpModeR::Base,
        &sk,
        &encap,
        PROVN_ZDR_INFO,
    )
    .and_then(|mut ctx| ctx.open(ciphertext, &[]))
}

/// Proxy seals a response back to the client using a completely new ephemeral session
pub fn hpke_seal(
    client_pubkey: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), hpke::HpkeError> {
    let pk = <KemImpl as Kem>::PublicKey::from_bytes(client_pubkey)
        .map_err(|_| hpke::HpkeError::ValidationError)?;

    let (encapsulated_key, mut ctx) = hpke::setup_sender::<AeadImpl, KdfImpl, KemImpl, _>(
        &hpke::OpModeS::Base,
        &pk,
        PROVN_ZDR_INFO,
        &mut OsRng,
    )?;

    let ciphertext = ctx.seal(plaintext, &[])?;

    Ok((encapsulated_key.to_bytes().to_vec(), ciphertext))
}
