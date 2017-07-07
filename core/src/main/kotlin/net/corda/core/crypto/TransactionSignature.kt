package net.corda.core.crypto

import java.security.InvalidKeyException
import java.security.SignatureException

/**
 * A wrapper around a digital signature accompanied with metadata, see [MerkleRootWithMeta] and [DigitalSignature].
 * The signature protocol works as follows: s = sign(MetaData.hashBytes).
 */
open class TransactionSignature(val signatureData: ByteArray, val merkleRootWithMeta: MerkleRootWithMeta) : DigitalSignature(signatureData) {
    /**
     * Function to auto-verify a [MerkleRootWithMeta] object's signature.
     * Note that [MerkleRootWithMeta] contains both public key and merkle root of the transaction.
     * @throws InvalidKeyException if the key is invalid.
     * @throws SignatureException if this signatureData object is not initialized properly,
     * the passed-in signatureData is improperly encoded or of the wrong type,
     * if this signatureData algorithm is unable to process the input data provided, etc.
     * @throws IllegalArgumentException if the signature scheme is not supported for this private key or if any of the clear or signature data is empty.
     */
    @Throws(InvalidKeyException::class, SignatureException::class)
    fun verify(): Boolean = Crypto.doVerify(this.merkleRootWithMeta.transactionMeta.publicKey, this.merkleRootWithMeta.merkleRoot, this)
}
