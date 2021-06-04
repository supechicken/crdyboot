// Background: the plan to use vboot_reference directly isn't going so
// hot, it seems we don't have a good way to link C code in with the
// Rust uefi target.
//
// So, now we see how hard it would be to write the verification in Rust.
//
// For now only the crypto operations are focused on.

// TODO: for now only VB2_ALG_RSA8192_SHA256 is supported

// Note: unlike the C code this is based on, I haven't bothered to use
// pointers everywhere so that data is rarely copied. I don't think
// these small copies are likely to slow anything down, and I don't
// think there should be any security issue either.

// TODO: can we make very restrictive checks on the ranges pointed to
// from headers? That seems like a place where security holes might
// lie.

// TODO: check that data outside what is covered by the signature is
// not trusted.

// TODO: use constants from vboot_reference for verification, maybe
// also offset_of for member fields?

// TODO: for now only VB2_ALG_RSA8192_SHA256 is supported.

// TODO
#![allow(dead_code)]

use {
    crate::vboot_sys::*,
    alloc::vec::Vec,
    core::{convert::TryInto, mem},
    memoffset::offset_of,
    rsa::PublicKey as _,
    sha2::{Digest, Sha256},
};

#[derive(Debug)]
enum CryptoError {
    UnsupportedAlgorithm(vb2_crypto_algorithm),
    BufferTooSmall,
    InvalidKeyData,
    InvalidKey(rsa::errors::Error),
    BadMagic,
    BadVersion,
    BadSignatureSize(usize, usize),
    SignatureVerificationFailed(rsa::errors::Error),
    KeyBlockNotCompletelySigned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Rsa8192Sha256,
}

impl Algorithm {
    fn from_vb2(alg: vb2_crypto_algorithm) -> Result<Algorithm, CryptoError> {
        if alg == vb2_crypto_algorithm::VB2_ALG_RSA8192_SHA256 {
            Ok(Algorithm::Rsa8192Sha256)
        } else {
            Err(CryptoError::UnsupportedAlgorithm(alg))
        }
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        match self {
            Algorithm::Rsa8192Sha256 => rsa::PaddingScheme::PKCS1v15Sign {
                hash: Some(rsa::Hash::SHA2_256),
            },
        }
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::Rsa8192Sha256 => Sha256::digest(data).to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureKind {
    /// SHA-512 hash (not signed).
    Sha512,

    /// RSA-8192 signature.
    Rsa8192,
}

impl SignatureKind {
    fn size_in_bytes(&self) -> usize {
        match self {
            SignatureKind::Sha512 => 512 / 8,

            // Based on vb2_rsa_sig_size (2lib/2rsa.c).
            SignatureKind::Rsa8192 => 8192 / 8,
        }
    }
}

fn u32_to_usize(v: u32) -> usize {
    // OK to unwrap since u32 should always fit in usize on the
    // required targets.
    v.try_into().unwrap()
}

fn u64_to_usize(v: u64) -> usize {
    // OK to unwrap since u64 should always fit in usize on the
    // required targets.
    v.try_into().unwrap()
}

fn read_u32_from_le_bytes(buf: &[u8], offset: usize) -> u32 {
    let slice = &buf[offset..offset + 4];
    let array: [u8; 4] = slice.try_into().unwrap();
    u32::from_le_bytes(array)
}

/// Get an &T backed by a byte slice. The slice is checked to make
/// sure it's at leas as large as the size of T. This can only be
/// called safely on repr(C) structs whose fields are either numeric
/// or structures that also meet these restrictions (recursively).
///
/// Rust is frustratingly unclear about what is UB, so I'm not sure
/// that this function is actually safe to call under the
/// circumstances outlined above. In particular I'm not clear on
/// whether it's OK to have two immutable refs to the same underlying
/// data with different types.
///
/// TODO: get this reviewed by a Rust unsafe expert.
unsafe fn transmute_from_bytes<T>(buf: &[u8]) -> Result<&T, CryptoError> {
    if buf.len() < mem::size_of::<T>() {
        return Err(CryptoError::BufferTooSmall);
    }

    let ptr = buf.as_ptr() as *const T;

    Ok(&*ptr)
}

#[derive(Debug, PartialEq)]
struct Signature {
    /// Raw signature data.
    signature: Vec<u8>,

    /// Size of the data covered by the signature.
    data_size: usize,
}

impl Signature {
    /// Load a Signature from a byte slice. The slice starts
    /// with the header, and must include the signature data as well
    /// (it doesn't have to include the data signed by the signature
    /// though).
    ///
    /// See 2lib/include/2struct.h for the declaration of
    /// `struct vb2_signature`.
    fn from_le_bytes(
        buf: &[u8],
        kind: SignatureKind,
    ) -> Result<Signature, CryptoError> {
        let header = unsafe { transmute_from_bytes::<vb2_signature>(buf) }?;

        let sig_offset = u32_to_usize(header.sig_offset);
        let sig_size = u32_to_usize(header.sig_size);
        let data_size = u32_to_usize(header.data_size);

        let sig_range = sig_offset..sig_offset + sig_size;
        let sig_data = buf.get(sig_range).ok_or(CryptoError::BufferTooSmall)?;

        if sig_data.len() != kind.size_in_bytes() {
            return Err(CryptoError::BadSignatureSize(
                sig_data.len(),
                kind.size_in_bytes(),
            ));
        }

        Ok(Signature {
            signature: sig_data.to_vec(),
            data_size,
        })
    }
}

#[derive(Debug, PartialEq)]
struct PublicKey {
    key: rsa::RSAPublicKey,
    algorithm: Algorithm,
    // TODO: using this for anything?
    key_version: u32,
}

impl PublicKey {
    /// Load a PublicKey from a byte slice. The slice starts with the
    /// header and must include the key data as well.
    ///
    /// Based on vb2_unpack_key_buffer (2lib/2packed_key.c).
    ///
    /// See 2lib/include/2struct.h for the declaration of
    /// `struct vb2_packed_key`.
    fn from_le_bytes(buf: &[u8]) -> Result<PublicKey, CryptoError> {
        let header = unsafe { transmute_from_bytes::<vb2_packed_key>(buf) }?;

        let key_offset = u32_to_usize(header.key_offset);
        let key_size = u32_to_usize(header.key_size);
        let algorithm =
            Algorithm::from_vb2(vb2_crypto_algorithm(header.algorithm))?;
        let key_version = header.key_version;

        let key_range = key_offset..key_offset + key_size;
        let key_data = buf.get(key_range).ok_or(CryptoError::BufferTooSmall)?;

        // The first four bytes contain the array size (pretending each
        // element is a u32).
        let arrsize = u32::from_le_bytes(
            key_data
                .get(0..4)
                .ok_or(CryptoError::InvalidKeyData)?
                .try_into()
                // Unwrap: just successfully got 4 bytes, so this cannot fail.
                .unwrap(),
        );

        // Multiply by 4 because we want to treat the u8 array as if it
        // were a u32 array.
        let n_start: usize = 2 * 4;
        let n_end = n_start + u32_to_usize(arrsize * 4);

        let n = rsa::BigUint::from_bytes_le(
            key_data
                .get(n_start..n_end)
                .ok_or(CryptoError::InvalidKeyData)?,
        );
        // F4 exponent.
        let e = rsa::BigUint::from_slice(&[65537]);

        let key =
            rsa::RSAPublicKey::new(n, e).map_err(CryptoError::InvalidKey)?;

        Ok(PublicKey {
            key,
            algorithm,
            key_version,
        })
    }

    /// Verify that the signature of `data_to_verify` matches the
    /// `expected_signature`.
    fn verify_all(
        &self,
        data_to_verify: &[u8],
        expected_signature: &Signature,
    ) -> Result<(), CryptoError> {
        // Get hash of the data covered by the signature.
        let digest = self.algorithm.digest(data_to_verify);

        self.key
            .verify(
                self.algorithm.padding_scheme(),
                &digest,
                &expected_signature.signature,
            )
            .map_err(CryptoError::SignatureVerificationFailed)
    }

    /// Verify that the signature of the first `signature.data_size`
    /// bytes of `buf` matches `signature.signature`.
    fn verify_partial(
        &self,
        buf: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        let data_to_verify = buf
            .get(..signature.data_size)
            .ok_or(CryptoError::BufferTooSmall)?;

        self.verify_all(data_to_verify, &signature)
    }
}

#[derive(Debug, PartialEq)]
struct KeyBlockHeader {
    keyblock_size: usize,
    keyblock_signature: Signature,
    keyblock_hash: Signature,
    keyblock_flags: u32,
    data_key: PublicKey,
}

impl KeyBlockHeader {
    /// Load a KeyBlockHeader from a byte slice. The slice starts with
    /// the header and needs to include the data key and signature
    /// data as well.
    ///
    /// See 2lib/include/2struct.h for the declaration of
    /// `struct vb2_keyblock`.
    fn from_le_bytes(buf: &[u8]) -> Result<KeyBlockHeader, CryptoError> {
        let header = unsafe { transmute_from_bytes::<vb2_keyblock>(buf) }?;

        if &header.magic != b"CHROMEOS" {
            return Err(CryptoError::BadMagic);
        }

        // Copying the logic from `vb2_check_keyblock`, only check the
        // major version.
        if header.header_version_major != 2 {
            return Err(CryptoError::BadVersion);
        }

        let header = KeyBlockHeader {
            keyblock_size: u32_to_usize(header.keyblock_size),
            keyblock_signature: Signature::from_le_bytes(
                &buf[offset_of!(vb2_keyblock, keyblock_signature)..],
                SignatureKind::Rsa8192,
            )?,
            keyblock_hash: Signature::from_le_bytes(
                &buf[offset_of!(vb2_keyblock, keyblock_hash)..],
                SignatureKind::Sha512,
            )?,
            keyblock_flags: header.keyblock_flags,
            data_key: PublicKey::from_le_bytes(
                &buf[offset_of!(vb2_keyblock, data_key)..],
            )?,
        };

        // The signature should cover the entire keyblock buffer,
        // except for the two signatures at the end.
        if header.keyblock_signature.data_size
            != header.keyblock_size
                - header.keyblock_signature.signature.len()
                - header.keyblock_hash.signature.len()
        {
            return Err(CryptoError::KeyBlockNotCompletelySigned);
        }

        // TODO: are other checks from `vb2_check_keyblock` needed?

        Ok(header)
    }
}

/// Verify a keyblock using a public key. If successful, the parsed
/// KeyBlockHeader is returned.
///
/// Based on vb2_verify_keyblock (2lib/2common.c).
///
/// See 2lib/include/2struct.h for the declaration of `struct
/// vb2_keyblock`.
fn verify_keyblock(
    buf: &[u8],
    key: &PublicKey,
) -> Result<KeyBlockHeader, CryptoError> {
    let header = KeyBlockHeader::from_le_bytes(buf)?;

    key.verify_partial(buf, &header.keyblock_signature)?;

    Ok(header)
}

// vb2_verify_kernel_vblock (lib/vboot_kernel.c)
pub fn verify_kernel_vblock() {
    // TODO: check flags
    // Check preamble
    // Check body
}

#[cfg(test)]
mod tests {
    use {super::*, core::convert::TryFrom};

    #[test]
    fn test_unpack_key_buffer() {
        // Decode the PEM-encoded public key.
        let test_key_pub_pem =
            include_bytes!("../test_data/kernel_key.pub.pem");
        let pem = rsa::pem::parse(test_key_pub_pem).unwrap();
        let expected_public_key = rsa::RSAPublicKey::try_from(pem).unwrap();

        // Decode the vbpubk-encoded public key.
        let test_key_vbpubk = include_bytes!("../test_data/kernel_key.vbpubk");
        let public_key = PublicKey::from_le_bytes(test_key_vbpubk).unwrap();

        // The two keys should be identical, just different file
        // representations.
        assert_eq!(public_key.key, expected_public_key);
    }

    #[test]
    fn test_keyblock_header() -> Result<(), CryptoError> {
        let test_keyblock =
            include_bytes!("../test_data/kernel_data_key.keyblock");

        let test_key_vbpubk =
            include_bytes!("../test_data/kernel_data_key.vbpubk");
        let public_key = PublicKey::from_le_bytes(test_key_vbpubk).unwrap();

        let header = KeyBlockHeader::from_le_bytes(test_keyblock)?;
        assert_eq!(header.keyblock_size, 3256);
        assert_eq!(header.keyblock_flags, 5);
        assert_eq!(header.keyblock_signature.data_size, 2168);
        assert_eq!(header.data_key, public_key);
        Ok(())
    }

    #[test]
    fn test_verify_keyblock() {
        // Get the public key whose private half was used to sign the
        // keyblock.
        let test_key_pub_pem =
            include_bytes!("../test_data/kernel_key.pub.pem");
        let pem = rsa::pem::parse(test_key_pub_pem).unwrap();
        let public_key = PublicKey {
            algorithm: Algorithm::Rsa8192Sha256,
            key: rsa::RSAPublicKey::try_from(pem).unwrap(),
            key_version: 0,
        };

        // Get the signed keyblock.
        let test_keyblock =
            include_bytes!("../test_data/kernel_data_key.keyblock");

        verify_keyblock(test_keyblock, &public_key).unwrap();
    }
}
