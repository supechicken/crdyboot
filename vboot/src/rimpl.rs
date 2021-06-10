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
// these small copies are likely to slow anything down.

// TODO: can we make very restrictive checks on the ranges pointed to
// from headers? That seems like a place where security holes might
// lie.

// TODO: check that data outside what is covered by the signature is
// not trusted.

// TODO: use constants from vboot_reference for verification, maybe
// also offset_of for member fields?

use {
    crate::vboot_sys,
    alloc::vec::Vec,
    core::{convert::TryInto, mem},
    memoffset::offset_of,
    rsa::PublicKey as _,
    sha2::{Digest, Sha256},
};

#[derive(Debug)]
pub enum VbootError {
    UnsupportedAlgorithm(vboot_sys::vb2_crypto_algorithm),
    BufferTooSmall,
    InvalidKeyData,
    InvalidKey(rsa::errors::Error),
    BadMagic,
    BadVersion,
    BadKeySize,
    BadKeyArraySize,
    BadSignatureSize,
    SignatureVerificationFailed(rsa::errors::Error),
    KeyBlockNotCompletelySigned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Rsa8192Sha256,
}

impl Algorithm {
    fn from_vb2(
        alg: vboot_sys::vb2_crypto_algorithm,
    ) -> Result<Algorithm, VbootError> {
        if alg == vboot_sys::vb2_crypto_algorithm::VB2_ALG_RSA8192_SHA256 {
            Ok(Algorithm::Rsa8192Sha256)
        } else {
            Err(VbootError::UnsupportedAlgorithm(alg))
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

    fn signature_kind(&self) -> SignatureKind {
        match self {
            Algorithm::Rsa8192Sha256 => SignatureKind::Rsa8192,
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

fn u64_to_usize(v: u64) -> usize {
    // OK to unwrap since u32 should always fit in usize on the
    // required targets.
    v.try_into().unwrap()
}

fn u32_to_usize(v: u32) -> usize {
    // OK to unwrap since u32 should always fit in usize on the
    // required targets.
    v.try_into().unwrap()
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
unsafe fn struct_from_bytes<T>(buf: &[u8]) -> Result<&T, VbootError> {
    if buf.len() < mem::size_of::<T>() {
        return Err(VbootError::BufferTooSmall);
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
    /// Based in part on `vb2_verify_digest` (2lib/2common.c).
    ///
    /// See 2lib/include/2struct.h for the declaration of
    /// `struct vb2_signature`.
    fn from_le_bytes(
        buf: &[u8],
        kind: SignatureKind,
    ) -> Result<Signature, VbootError> {
        let header =
            unsafe { struct_from_bytes::<vboot_sys::vb2_signature>(buf) }?;

        let sig_offset = u32_to_usize(header.sig_offset);
        let sig_size = u32_to_usize(header.sig_size);
        let data_size = u32_to_usize(header.data_size);

        let sig_range = sig_offset..sig_offset + sig_size;
        let sig_data = buf.get(sig_range).ok_or(VbootError::BufferTooSmall)?;

        if sig_data.len() != kind.size_in_bytes() {
            return Err(VbootError::BadSignatureSize);
        }

        Ok(Signature {
            signature: sig_data.to_vec(),
            data_size,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    key: rsa::RSAPublicKey,
    algorithm: Algorithm,
    // TODO: using this for anything?
    key_version: u32,
}

impl PublicKey {
    /// Load a PublicKey from a byte slice. The slice starts with the
    /// `vb2_packed_key` header and must include the key data as well.
    ///
    /// Based on vb2_unpack_key_buffer (2lib/2packed_key.c).
    ///
    /// See 2lib/include/2struct.h for the declaration of
    /// `struct vb2_packed_key`.
    pub fn from_le_bytes(buf: &[u8]) -> Result<PublicKey, VbootError> {
        let header =
            unsafe { struct_from_bytes::<vboot_sys::vb2_packed_key>(buf) }?;

        let key_offset = u32_to_usize(header.key_offset);
        let key_size = u32_to_usize(header.key_size);
        let algorithm = Algorithm::from_vb2(vboot_sys::vb2_crypto_algorithm(
            header.algorithm,
        ))?;
        let key_version = header.key_version;

        // Based on `vb2_packed_key_size` (2lib/2rsa.c).
        let expected_key_size = 2 * algorithm.signature_kind().size_in_bytes()
            + 2 * mem::size_of::<u32>();
        if key_size != expected_key_size {
            return Err(VbootError::BadKeySize);
        }

        let key_range = key_offset..key_offset + key_size;
        let key_data = buf.get(key_range).ok_or(VbootError::BufferTooSmall)?;

        // The first four bytes contain the array size (pretending each
        // element is a u32).
        let arrsize = u32::from_le_bytes(
            key_data
                .get(0..4)
                .ok_or(VbootError::InvalidKeyData)?
                .try_into()
                // Unwrap: just successfully got 4 bytes, so this cannot fail.
                .unwrap(),
        );

        // Validity check key array size.
        if u32_to_usize(arrsize) * mem::size_of::<u32>()
            != algorithm.signature_kind().size_in_bytes()
        {
            return Err(VbootError::BadKeyArraySize);
        }

        // Multiply by 4 because we want to treat the u8 array as if it
        // were a u32 array.
        let n_start: usize = 2 * 4;
        let n_end = n_start + u32_to_usize(arrsize * 4);

        let n = rsa::BigUint::from_bytes_le(
            key_data
                .get(n_start..n_end)
                .ok_or(VbootError::InvalidKeyData)?,
        );
        // F4 exponent.
        let e = rsa::BigUint::from_slice(&[65537]);

        let key =
            rsa::RSAPublicKey::new(n, e).map_err(VbootError::InvalidKey)?;

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
    ) -> Result<(), VbootError> {
        // Get hash of the data covered by the signature.
        let digest = self.algorithm.digest(data_to_verify);

        self.key
            .verify(
                self.algorithm.padding_scheme(),
                &digest,
                &expected_signature.signature,
            )
            .map_err(VbootError::SignatureVerificationFailed)
    }

    /// Verify that the signature of the first `signature.data_size`
    /// bytes of `buf` matches `signature.signature`.
    fn verify_partial(
        &self,
        buf: &[u8],
        signature: &Signature,
    ) -> Result<(), VbootError> {
        let data_to_verify = buf
            .get(..signature.data_size)
            .ok_or(VbootError::BufferTooSmall)?;

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
    /// the `vb2_keyblock` header and needs to include the data key
    /// and signature data as well.
    ///
    /// After the header is parsed, its signature is checked against
    /// `key`, and an error is returned if validation fails.
    ///
    /// See 2lib/include/2struct.h for the declaration of
    /// `struct vb2_keyblock`.
    ///
    /// Based in part on vb2_verify_keyblock (2lib/2common.c).
    fn parse_and_verify(
        buf: &[u8],
        key: &PublicKey,
    ) -> Result<KeyBlockHeader, VbootError> {
        let header =
            unsafe { struct_from_bytes::<vboot_sys::vb2_keyblock>(buf) }?;

        if &header.magic != b"CHROMEOS" {
            return Err(VbootError::BadMagic);
        }

        // Copying the logic from `vb2_check_keyblock`, only check the
        // major version.
        if header.header_version_major != vboot_sys::VB2_KEYBLOCK_VERSION_MAJOR
        {
            return Err(VbootError::BadVersion);
        }

        let header = KeyBlockHeader {
            keyblock_size: u32_to_usize(header.keyblock_size),
            keyblock_signature: Signature::from_le_bytes(
                &buf[offset_of!(vboot_sys::vb2_keyblock, keyblock_signature)..],
                key.algorithm.signature_kind(),
            )?,
            keyblock_hash: Signature::from_le_bytes(
                &buf[offset_of!(vboot_sys::vb2_keyblock, keyblock_hash)..],
                SignatureKind::Sha512,
            )?,
            keyblock_flags: header.keyblock_flags,
            data_key: PublicKey::from_le_bytes(
                &buf[offset_of!(vboot_sys::vb2_keyblock, data_key)..],
            )?,
        };

        // The signature should cover the entire keyblock buffer,
        // except for the two signatures at the end.
        if header.keyblock_signature.data_size
            != header.keyblock_size
                - header.keyblock_signature.signature.len()
                - header.keyblock_hash.signature.len()
        {
            return Err(VbootError::KeyBlockNotCompletelySigned);
        }

        key.verify_partial(buf, &header.keyblock_signature)?;

        // TODO: are other checks from `vb2_check_keyblock` needed?

        Ok(header)
    }
}

#[derive(Debug, PartialEq)]
struct KernelPreamble {
    preamble_size: usize,
    preamble_signature: Signature,
    body_signature: Signature,
    command_line_start: usize,
}

impl KernelPreamble {
    /// Load a KernelPreamble from a byte slice. The slice starts with
    /// the vb2_kernel_preamble structure and includes the data for
    /// the body and preamble signatures.
    ///
    /// After the preamble is parsed, its signature is checked against
    /// the data key from `keyblock`, and an error is returned if
    /// validation fails.
    ///
    /// Based on `vb2_verify_kernel_preamble` (lib20/kernel.c).
    fn parse_and_verify(
        buf: &[u8],
        keyblock: &KeyBlockHeader,
    ) -> Result<KernelPreamble, VbootError> {
        let header = unsafe {
            struct_from_bytes::<vboot_sys::vb2_kernel_preamble>(buf)
        }?;

        if header.header_version_major
            != vboot_sys::VB2_KERNEL_PREAMBLE_HEADER_VERSION_MAJOR
        {
            return Err(VbootError::BadVersion);
        }
        if header.header_version_minor
            != vboot_sys::VB2_KERNEL_PREAMBLE_HEADER_VERSION_MINOR
        {
            return Err(VbootError::BadVersion);
        }

        // Based on `UnpackKernelBlob` in futility/vb1_helper.c.
        let command_line_start = u64_to_usize(header.bootloader_address)
            - u64_to_usize(header.body_load_address)
            - u32_to_usize(vboot_sys::CROS_PARAMS_SIZE)
            - u32_to_usize(vboot_sys::CROS_CONFIG_SIZE);

        let preamble = KernelPreamble {
            preamble_size: u32_to_usize(header.preamble_size),
            preamble_signature: Signature::from_le_bytes(
                &buf[offset_of!(
                    vboot_sys::vb2_kernel_preamble,
                    preamble_signature
                )..],
                keyblock.data_key.algorithm.signature_kind(),
            )?,
            body_signature: Signature::from_le_bytes(
                &buf[offset_of!(
                    vboot_sys::vb2_kernel_preamble,
                    body_signature
                )..],
                keyblock.data_key.algorithm.signature_kind(),
            )?,
            command_line_start,
        };

        // TODO: check what signature covers

        keyblock
            .data_key
            .verify_partial(buf, &preamble.preamble_signature)?;

        Ok(preamble)
    }
}

pub struct Kernel<'a> {
    pub data: &'a [u8],
    pub command_line: &'a str,
}

// TODO: think about naming
// vb2_verify_kernel_vblock (lib/vboot_kernel.c)
//
// Returns the kernel body data. TODO: for now it is actually
// returning `buf[kernel_body_data..]`.
pub fn verify_kernel<'a>(
    buf: &'a [u8],
    key: &PublicKey,
) -> Result<Kernel<'a>, VbootError> {
    let keyblock = KeyBlockHeader::parse_and_verify(buf, key)?;

    let rest = buf
        .get(keyblock.keyblock_size..)
        .ok_or(VbootError::BufferTooSmall)?;

    let preamble = KernelPreamble::parse_and_verify(rest, &keyblock)?;

    // Verify the body (kernel code, config, bootloader).
    let body = rest
        .get(preamble.preamble_size..)
        .ok_or(VbootError::BufferTooSmall)?;
    keyblock
        .data_key
        .verify_partial(body, &preamble.body_signature)?;

    let command_line = body
        .get(
            preamble.command_line_start
                ..preamble.command_line_start
                    + u32_to_usize(vboot_sys::CROS_CONFIG_SIZE),
        )
        .ok_or(VbootError::BufferTooSmall)?;

    // Find the null terminator.
    //
    // TODO: don't unwrap
    let command_line_end = command_line.iter().position(|b| *b == 0).unwrap();
    let command_line =
        core::str::from_utf8(&command_line[..command_line_end]).unwrap();

    // TODO: check version/flags/etc

    Ok(Kernel {
        data: body,
        command_line,
    })
}

#[cfg(test)]
mod tests {
    use {super::*, core::convert::TryFrom};

    fn key_from_pem_bytes(pem_bytes: &[u8]) -> PublicKey {
        let pem = rsa::pem::parse(pem_bytes).unwrap();
        PublicKey {
            algorithm: Algorithm::Rsa8192Sha256,
            key: rsa::RSAPublicKey::try_from(pem).unwrap(),
            key_version: 1,
        }
    }

    #[test]
    fn test_unpack_key_buffer() {
        // Decode the PEM-encoded public key.
        let test_key_pub_pem =
            include_bytes!("../test_data/kernel_key.pub.pem");
        let expected_public_key = key_from_pem_bytes(test_key_pub_pem);

        // Decode the vbpubk-encoded public key.
        let test_key_vbpubk = include_bytes!("../test_data/kernel_key.vbpubk");
        let public_key = PublicKey::from_le_bytes(test_key_vbpubk).unwrap();

        // The two keys should be identical, just different file
        // representations.
        assert_eq!(public_key.key, expected_public_key.key);
    }

    #[test]
    fn test_verify_keyblock() {
        // Get the public key whose private half was used to sign the
        // keyblock.
        let kernel_key_pub_pem =
            include_bytes!("../test_data/kernel_key.pub.pem");
        let kernel_key = key_from_pem_bytes(kernel_key_pub_pem);

        // Get the public key for the kernel data.
        let kernel_data_key_pub_pem =
            include_bytes!("../test_data/kernel_data_key.pub.pem");
        let kernel_data_key = key_from_pem_bytes(kernel_data_key_pub_pem);

        // Get the signed keyblock.
        let test_keyblock =
            include_bytes!("../test_data/kernel_data_key.keyblock");

        let header =
            KeyBlockHeader::parse_and_verify(test_keyblock, &kernel_key)
                .unwrap();
        assert_eq!(header.keyblock_size, 3256);
        assert_eq!(header.keyblock_flags, 5);
        assert_eq!(header.keyblock_signature.data_size, 2168);
        assert_eq!(header.data_key, kernel_data_key);
    }

    #[test]
    fn test_verify_kernel() {
        // Get the public key whose private half was used to sign the
        // keyblock.
        let kernel_key_pub_pem =
            include_bytes!("../test_data/kernel_key.pub.pem");
        let kernel_key = key_from_pem_bytes(kernel_key_pub_pem);

        // Get the signed kernel.
        let test_kernel = include_bytes!("../test_data/fake_signed_kernel");

        verify_kernel(test_kernel, &kernel_key).unwrap();
    }
}
