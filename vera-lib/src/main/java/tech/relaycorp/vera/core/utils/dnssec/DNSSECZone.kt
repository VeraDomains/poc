package tech.relaycorp.vera.core.utils.dnssec

import org.xbill.DNS.RRset
import tech.relaycorp.vera.core.dns.rrsetsToASN1
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils

data class DNSSECZone(val dsRRSet: List<RRset>, val dnskeyRRSet: List<RRset>) {
    fun toASN1Sequence() = ASN1Utils.makeSequence(
        listOf(dsRRSet.rrsetsToASN1(), dnskeyRRSet.rrsetsToASN1())
    )
}
