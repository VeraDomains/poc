package tech.relaycorp.vera.core.utils.dnssec

import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.charset.Charset
import java.time.Instant
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.withContext
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Master
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.RRset
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.SRRset
import org.xbill.DNS.dnssec.SecurityStatus
import org.xbill.DNS.dnssec.ValUtils
import org.xbill.DNS.dnssec.ValidatingResolver
import tech.relaycorp.vera.core.SignatureVerificationException
import tech.relaycorp.vera.core.VeraException

internal class DNSSECLookup(
    val rootDNSKEY: RRset,
    val parentZones: List<DNSSECZone>,
    val rrset: RRset,
) {
    val lastSignatureDate: Instant by lazy {
        val allRRSets = listOf(rootDNSKEY, rrset) +
            parentZones.map { it.dsRRSet } +
            parentZones.map { it.dnskeyRRSet }
        val signatures = allRRSets.flatMap { it.sigs() }
        val signatureDates = signatures.map { it.timeSigned }.sorted()
        signatureDates.last()
    }

    /**
     * Verify that all RRSets were valid at the time of the last RRSig in the chain.
     */
    @Throws(SignatureVerificationException::class)
    fun verify() {
        verifyDNSKEY(rootDNSKEY, ROOT_DS_RRSET, lastSignatureDate)
        verifyRRSet(rootDNSKEY, rootDNSKEY, lastSignatureDate)

        parentZones.forEachIndexed { index, dnssecZone ->
            val dnskeyRRSet = if (index == 0)
                rootDNSKEY
            else
                parentZones[index - 1].dnskeyRRSet
            verifyRRSet(dnssecZone.dsRRSet, dnskeyRRSet, lastSignatureDate)
            verifyDNSKEY(dnssecZone.dnskeyRRSet, dnssecZone.dsRRSet, lastSignatureDate)
        }

        verifyRRSet(rrset, parentZones.last().dnskeyRRSet, lastSignatureDate)
    }

    companion object {
        private const val RESOLVER_ADDRESS = "8.8.8.8"

        // Taken from https://data.iana.org/root-anchors/root-anchors.xml
        private val DNSSEC_ROOT =
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
                .toByteArray(Charset.defaultCharset())

        private val ROOT_DS_RRSET = RRset(
            Master(ByteArrayInputStream(DNSSEC_ROOT), Name.root, 0)
                .nextRecord(),
        )

        private val RESOLVER = ValidatingResolver(SimpleResolver(RESOLVER_ADDRESS))

        private val SUBDOMAIN_REGEX = """^(?<subDomain>[^\\.]+\.)(?<parentDomain>([^\\.]+\.)+|)$""".toRegex()

        private val valUtils = ValUtils()

        init {
            RESOLVER.loadTrustAnchors(ByteArrayInputStream(DNSSEC_ROOT))
        }

        suspend fun lookUp(name: String, type: String): DNSSECLookup {
            val allZones = getZones(name)
            val rootDNSKEY = lookUpRRSet(allZones.first(), "DNSKEY")
            val parentZones = allZones.drop(1).dropLast(1).map { lookUpZone(it) }
            val rrset = lookUpRRSet(allZones.last(), type)
            return DNSSECLookup(rootDNSKEY, parentZones, rrset)
        }

        private fun getZones(name: String): List<Name> {
            val currentZone = Name.fromConstantString(name)
            val parentZones = if (name == ".") {
                emptyList()
            } else {
                val result = SUBDOMAIN_REGEX.matchEntire(name) ?: throw VeraException("Malformed name $name")
                val parentZoneName = result.groups["parentDomain"]!!.value
                getZones(parentZoneName.ifEmpty { "." })
            }
            return parentZones + listOf(currentZone)
        }

        private suspend fun lookUpZone(name: Name): DNSSECZone {
            val dsRRSet = if (name.toString(false) != "")
                lookUpRRSet(name, "DS")
            else
                RRset(
                    Record.newRecord(Name.fromConstantString("."), Type.DS, DClass.IN)
                )
            val dnskeyRRSet = lookUpRRSet(name, "DNSKEY")
            return DNSSECZone(dsRRSet, dnskeyRRSet)
        }

        @Throws(IOException::class)
        private suspend fun lookUpRRSet(name: Name, type: String): RRset {
            val recordType = Type.value(type)
            val queryRecord = Record.newRecord(name, recordType, DClass.IN)
            val response: Message = withContext(coroutineContext) {
                RESOLVER.send(Message.newQuery(queryRecord))
            }
            if (response.rcode != Rcode.NOERROR) {
                throw VeraException("DNS lookup failed (${Rcode.string(response.rcode)})")
            }
            val adFlag = response.header.getFlag(Flags.AD.toInt())
            if (!adFlag) {
                throw VeraException("DNSSEC validation failed")
            }
            val allRRSets = response.getSectionRRsets(Section.ANSWER)
            val relevantRRSet = try {
                allRRSets.single { it.type == recordType }
            } catch (exc: NoSuchElementException) {
                throw VeraException("$name/$type is unset")
            }
            return relevantRRSet
        }

        @Throws(SignatureVerificationException::class)
        private fun verifyDNSKEY(dnskeyRRSet: RRset, dsRRSet: RRset, date: Instant) {
            val signedRRSet = SRRset(dnskeyRRSet)
            val signedParentDNSKEY = SRRset(dsRRSet)
            val result = valUtils.verifyNewDNSKEYs(
                signedRRSet,
                signedParentDNSKEY,
                60,
                date,
            )
            if (!result.isGood()) {
                throw SignatureVerificationException(
                    "Invalid ${dnskeyRRSet.name}/DNSKEY"
                )
            }
        }

        @Throws(SignatureVerificationException::class)
        private fun verifyRRSet(rrset: RRset, dnskeyRRSet: RRset, date: Instant) {
            val signedRRSet = SRRset(rrset)
            val signedParentDNSKEY = SRRset(dnskeyRRSet)
            val result = valUtils.verifySRRset(
                signedRRSet,
                signedParentDNSKEY,
                date,
            )
            if (result.status != SecurityStatus.SECURE) {
                throw SignatureVerificationException(
                    "Invalid signature for ${rrset.name}/${Type.string(rrset.type)} (${result.status})"
                )
            }
        }
    }
}
