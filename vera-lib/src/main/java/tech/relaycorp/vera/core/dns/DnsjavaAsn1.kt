/**
 * ASN.1 serialisation utilities for dnsjava objects.
 */

package tech.relaycorp.vera.core.dns

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.xbill.DNS.RRset
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import tech.relaycorp.vera.core.utils.asn1.ASN1Utils

internal fun RRset.rrsetToASN1(): DERSequence {
    return ASN1Utils.makeSequence(
        (rrs().recordsToASN1() + sigs().recordsToASN1()),
        true,
    )
}

internal fun ASN1Encodable.asn1ToRRSet(): RRset {
    val sequence = if (this is ASN1Sequence)
        this
    else
        DERSequence.getInstance(this as ASN1TaggedObject, false)
    val records = sequence.map { it.asn1ToRecord() }.toTypedArray()
    return RRset(*records)
}

private fun List<Record>.recordsToASN1(): DERSequence {
    return ASN1Utils.makeSequence(map { it.recordToASN1() })
}

private fun Record.recordToASN1(): ASN1Encodable {
    return DEROctetString(toWire(Section.ANSWER))
}

private fun ASN1Encodable.asn1ToRecord(): Record {
    val recordASN1 = DEROctetString.getInstance(this)
    return Record.fromWire(recordASN1.octets, Section.ANSWER)
}
