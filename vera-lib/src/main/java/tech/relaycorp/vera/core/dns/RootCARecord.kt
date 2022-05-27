package tech.relaycorp.vera.core.dns

class RootCARecord(val domainName: String, val publicKeyDigest: RootKeyDigest) {
    val txtRecord get() = "vera.${domainName}.   IN   TXT   \"${publicKeyDigest.txtValue}\""
}
