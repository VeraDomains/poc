package tech.relaycorp.vera.core.utils.dnssec

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERSequence
import org.xbill.DNS.RRset
import tech.relaycorp.vera.core.dns.asn1ToRRSet
import tech.relaycorp.vera.core.dns.rrsetToASN1
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils

data class DNSSECZone(val dsRRSet: RRset, val dnskeyRRSet: RRset) {
    fun toASN1Sequence() = ASN1Utils.makeSequence(
        listOf(dsRRSet.rrsetToASN1(), dnskeyRRSet.rrsetToASN1()),
        false,
    )

    companion object {
        internal fun fromASN1(asn1: ASN1Encodable): DNSSECZone {
            val sequence = DERSequence.getInstance(asn1)
            val dsRRSet = DERSequence.getInstance(sequence.first() as ASN1TaggedObject, false).asn1ToRRSet()
            val dnskeyRRSet = DERSequence.getInstance(sequence.last() as ASN1TaggedObject, false).asn1ToRRSet()
            return DNSSECZone(dsRRSet, dnskeyRRSet)
        }
    }
}

internal fun List<DNSSECZone>.zonesToASN1() = ASN1Utils.makeSequence(map { it.toASN1Sequence() })

internal fun ASN1TaggedObject.asn1ToZones(): List<DNSSECZone> {
    val sequence = DERSequence.getInstance(this, false)
    return sequence.toList().map { DNSSECZone.fromASN1(it) }
}
