package tech.relaycorp.vera.core.utils.dnssec

import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.charset.Charset
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.withContext
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.RRset
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.Type
import org.xbill.DNS.dnssec.ValidatingResolver
import tech.relaycorp.vera.core.VeraException

internal class DNSSECLookup(
    val rrset: RRset,
    val parentZones: List<DNSSECZone>,
    val rootDNSKEY: RRset
) {

    companion object {
        private const val RESOLVER_ADDRESS = "8.8.8.8"

        // Taken from https://data.iana.org/root-anchors/root-anchors.xml
        private const val DNSSEC_ROOT =
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

        private val RESOLVER = ValidatingResolver(SimpleResolver(RESOLVER_ADDRESS))

        private val SUBDOMAIN_REGEX = """^(?<subDomain>[^\\.]+\.)(?<parentDomain>([^\\.]+\.)+|)$""".toRegex()

        init {
            RESOLVER.loadTrustAnchors(ByteArrayInputStream(DNSSEC_ROOT.toByteArray(Charset.defaultCharset())))
        }

        suspend fun lookUp(name: String, type: String): DNSSECLookup {
            val allZones = getZones(name)
            val rrset = lookUpRRSet(allZones.first(), type)
            val parentZones = allZones.drop(1).dropLast(1).map { lookUpZone(it) }
            val rootDNSKEY = lookUpRRSet(allZones.last(), "DNSKEY")
            return DNSSECLookup(rrset, parentZones, rootDNSKEY)
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
            return listOf(currentZone) + parentZones
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
    }
}
