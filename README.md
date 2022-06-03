
# Vera's proof of concept

This is a working, throwaway prototype of the core of [Vera](https://vera.domains), an offline authentication protocol incubated by [Relaycorp](https://relaycorp.tech). The purpose of this prototype is to inform the eventual implementation of the protocol by:

- Making sure that there's nothing that would make the implementation impossible or infeasible (e.g., key assumptions that turn out to be wrong, lack of tooling).
- Identifying the libraries, tools and systems that we could leverage in an eventual implementation, as well as the Vera-agnostic components that we'd have to build.
- Getting a sense of the effort required to implement the protocol.
- Understanding the data storage and data processing capacity required by the various components of the system.

[Read the wiki](https://github.com/VeraDomains/poc/wiki) to learn more about the outcome of this project.

## Prerequisites

- System dependencies: Bash, Java 8+ and OpenSSL.
- A domain with DNSSEC properly configure. Use [DNSSEC Analyzer](https://dnssec-analyzer.verisignlabs.com/) to check that DNSSEC is indeed working properly.

## Install

1. Install the project with `./gradlew build`.
3. Compile the CLIs with `./bin/compile-clis`.

## Usage

We'll use `chores.fans` as an example but make sure to use your own domain name.

### Provision Vera

First, as an Organisation Admin (OA) you have to provision Vera:

1. Generate a private key for your organisation and save it to `org-private-key.der`:
   ```shell
    ./bin/vera-ca key-gen chores.fans org-private-key.der
    ```
2. Go to your DNS hosting provider and create the `TXT` record output above.

### Issue a Vera Id to a member

The Organisation Member (OM) should first provision their Vera key pair:

1. Generate a private key and save it to `member-private-key.der`:
   ```shell
   openssl genpkey \
     -algorithm rsa-pss \
     -pkeyopt rsa_keygen_bits:2048 \
     -outform DER \
     -out member-private-key.der
   ```
2. Extract the public key and save it to `member-public-key.der`:
   ```shell
   openssl rsa -inform DER -in member-private-key.der -outform DER -pubout > member-public-key.der
   ```

Then the OA can issue a Vera Id to the OM (in the real world this would only be done after authenticating the OM):

1. Retrieve a DNSSEC chain for the `TXT` created above and save it to `dnssec-chain.der`:
   ```shell
   ./bin/vera-ca get-dnssec-chain chores.fans > dnssec-chain.der
   ```
   
   This chain can be cached and reused across Vera Ids, but the more recent the better since chains expire.
2. Generate a certificate for the organisation and save it to `org-certificate.der`:
   ```shell
    ./bin/vera-ca generate-root-ca chores.fans \
      <org-private-key.der > org-certificate.der
    ```

   This too can be cached and reused across Vera Ids, but the more recent the better.

   By default, the certificate will be valid for 90 days. To customise this, use the option `--ttl`; for example, `--ttl=30d` for 30 days.
3. Issue the id to the member (using their public key) and save it to `member-id.der`:
   ```shell
   ./bin/vera-ca issue-member-id \
     dnssec-chain.der \
     org-private-key.der \
     org-certificate.der \
     1.2.3.4.5 \
     <member-public-key.der >member-id.der
   ```
   
   `1.2.3.4.5` denotes the [Object Identifier (OID)](https://en.wikipedia.org/wiki/Object_identifier) for the _Vera service_ where this Vera Id is valid. For example, `1.3.6.1.4.1.58708.1.0` will probably be the OID for [Letro](https://letro.app/en/).
   
   By default, the OM is assumed to be a _bot_ that will act on behalf of the organisation in the context of the specified service. To issue an id to a _user_, pass the `--user-name` option; for example `--user-name=alice`.

   By default, the Vera Id will be valid for 30 days. To customise this, use the option `--ttl`; for example, `--ttl=7d` for 7 days or `--ttl=48h` for 48 hours.

### Produce Vera signature

An OM holding a Vera Id can sign a given plaintext as follows:

```shell
./bin/vera-app sign \
  member-private-key.der \
  member-id.der \
  <plaintext.txt >signature.der
```

Where:

- `plaintext.txt` is the file to be signed. It can be binary.
- `signature.der` will be the resulting Vera signature.

The OM can now share the two files above with anyone that wants to verify the authenticity of `plaintext.txt`.

### Verify Vera signature

TODO
