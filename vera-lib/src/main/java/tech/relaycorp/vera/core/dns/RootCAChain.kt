package tech.relaycorp.vera.core.dns

import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.core.utils.dnssec.DNSSECLookup
import tech.relaycorp.vera.core.utils.dnssec.asn1ToZones
import tech.relaycorp.vera.core.utils.dnssec.zonesToASN1

class RootCAChain internal constructor(private val dnssecLookup: DNSSECLookup) {
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

    companion object {
        suspend fun retrieve(domainName: String): RootCAChain {
            val lookup = DNSSECLookup.lookUp("_vera.$domainName.", "TXT")
            return RootCAChain(lookup)
        }

        fun deserialize(serialization: ByteArray): RootCAChain {
            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val rrset = sequence.first().asn1ToRRSet()
            val parentZones = sequence[1].asn1ToZones()
            val rootDNSKEY = sequence.last().asn1ToRRSet()
            val dnssecLookup = DNSSECLookup(rrset, parentZones, rootDNSKEY)
            return RootCAChain(dnssecLookup)
        }
    }
}
