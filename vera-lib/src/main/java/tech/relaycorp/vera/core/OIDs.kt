package tech.relaycorp.vera.core

import org.bouncycastle.asn1.ASN1ObjectIdentifier

internal object OIDs {
    private val RELAYCORP = ASN1ObjectIdentifier("1.3.6.1.4.1.58708")
    val VERA: ASN1ObjectIdentifier = RELAYCORP.branch("2")
}
