package tech.relaycorp.vera.core.dns

import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.core.utils.dnssec.DNSSECLookup

class RootCAChain internal constructor(private val dnssecLookup: DNSSECLookup) {
    fun serialise(): ByteArray {
        val sequence = ASN1Utils.makeSequence(
            listOf(
                dnssecLookup.rrset.rrsetsToASN1(),
                dnssecLookup.parentZones.zonesToASN1(),
                dnssecLookup.rootDNSKEY.rrsetsToASN1()
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
    }
}
