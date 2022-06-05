package tech.relaycorp.vera.core.dns

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class RootCAChainTest {
    @Test
    fun verification() = runBlocking {
        val chain = RootCAChain.retrieve("chores.fans")
        chain.verify()
    }

    @Test
    fun identity() = runBlocking {
        val chain = RootCAChain.retrieve("chores.fans")
        val chainSerialized = chain.serialise()

        val chain2 = RootCAChain.deserialize(chainSerialized)
        val chain2Serialized = chain2.serialise()

        assertArrayEquals(chainSerialized, chain2Serialized)
    }
}