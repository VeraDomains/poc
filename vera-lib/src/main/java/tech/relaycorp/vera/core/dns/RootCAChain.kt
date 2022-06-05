package tech.relaycorp.vera.core.dns

import java.time.ZoneOffset.UTC
import java.time.ZonedDateTime
import org.xbill.DNS.Record
import org.xbill.DNS.Type
import tech.relaycorp.vera.core.SignatureVerificationException
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.core.utils.dnssec.DNSSECLookup
import tech.relaycorp.vera.core.utils.dnssec.asn1ToZones
import tech.relaycorp.vera.core.utils.dnssec.zonesToASN1

class RootCAChain internal constructor(private val dnssecLookup: DNSSECLookup) {
    private val veraTxtRecord: Record by lazy { dnssecLookup.rrset.rrs().single() }
    private val veraTxtParts: List<String> by lazy {
        veraTxtRecord.rdataToString().removeSurrounding("\"").split(" ")
    }

    val domainName get() = veraTxtRecord.name.toString(true).removePrefix("_vera.")
    val publicKeySpec get() = veraTxtParts.first()

    val startDate get(): ZonedDateTime = dnssecLookup.lastSignatureDate.atZone(UTC)
    val expiryDate get(): ZonedDateTime = startDate.plusSeconds(veraTxtParts.last().toLong())

    fun serialise(): ByteArray {
        val sequence = ASN1Utils.makeSequence(
            listOf(
                dnssecLookup.rrset.rrsetToASN1(),
                dnssecLookup.parentZones.zonesToASN1(),
                dnssecLookup.rootDNSKEY.rrsetToASN1()
            ),
            false
        )
        return sequence.encoded
    }

    @Throws(SignatureVerificationException::class)
    fun verify() {
        dnssecLookup.verify()

        validateRecord(veraTxtRecord)
    }

    @Throws(SignatureVerificationException::class)
    private fun validateRecord(veraTxtRecord: Record) {
        val recordName = veraTxtRecord.name.toString()
        if (!recordName.startsWith("_vera.")) {
            throw SignatureVerificationException(
                "Invalid Vera record name ($recordName)",
            )
        }

        if (veraTxtRecord.type != Type.TXT) {
            throw SignatureVerificationException(
                "Invalid Vera record type (${Type.string(veraTxtRecord.type)})",
            )
        }
    }

    companion object {
        suspend fun retrieve(domainName: String): RootCAChain {
            val lookup = DNSSECLookup.lookUp("_vera.$domainName.", "TXT")
            val chain = RootCAChain(lookup)
            chain.verify()
            return chain
        }

        fun deserialize(serialization: ByteArray): RootCAChain {
            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val rrset = sequence.first().asn1ToRRSet()
            val parentZones = sequence[1].asn1ToZones()
            val rootDNSKEY = sequence.last().asn1ToRRSet()
            val dnssecLookup = DNSSECLookup(rootDNSKEY, parentZones, rrset)
            return RootCAChain(dnssecLookup)
        }
    }
}
