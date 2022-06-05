package tech.relaycorp.vera.core.utils.dnssec

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class DNSSECLookupTest {
    @Test
    fun test() = runBlocking {
        val lookup = DNSSECLookup.lookUp("_vera.chores.fans.", "TXT")
        lookup.verify()
    }
}
