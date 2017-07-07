package net.corda.core.crypto

import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.serialize
import java.security.PublicKey

/**
 * TransactionMeta is required to add extra meta-data to a transaction.
 * It currently supports platformVersiona and signer's public key, but it can be extended to support a universal digital
 * signature model enabling partial signatures and attaching extra information, such as a user's timestamp or other
 * application-specific fields.
 *
 * @param platformVersion current version of DLT used when signing.
 * @param publicKey signer's public key.
 */
@CordaSerializable
open class TransactionMeta(val platformVersion: Int, val publicKey: PublicKey) {

    fun bytes() = this.serialize().bytes

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransactionMeta) return false
        return platformVersion == other.platformVersion && publicKey == other.publicKey
    }

    override fun hashCode(): Int {
        var result = platformVersion
        result = 31 * result + publicKey.hashCode()
        return result
    }

    override fun toString(): String {
        return "TransactionMeta(platformVersion=$platformVersion, publicKey=${publicKey.toStringShort()})"
    }
}
