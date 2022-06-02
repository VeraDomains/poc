package tech.relaycorp.vera.core.dns

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERVisibleString
import org.xbill.DNS.RRset
import org.xbill.DNS.Record
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils
import tech.relaycorp.vera.core.utils.dnssec.DNSSECZone

internal fun List<RRset>.rrsetsToASN1(): DERSequence {
    return ASN1Utils.makeSequence(
        map { it.rrs().recordsToASN1() } + map { it.sigs().recordsToASN1() }
    )
}

internal fun List<Record>.recordsToASN1(): DERSequence {
    return ASN1Utils.makeSequence(map { it.toASN1() })
}

internal fun List<DNSSECZone>.zonesToASN1() = ASN1Utils.makeSequence(map { it.toASN1Sequence() })

internal fun Record.toASN1(): ASN1Encodable {
    // Use OCTET STRING in production
    return DERVisibleString(toString())
}
