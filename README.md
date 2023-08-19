# A simple Veilid DHT chat demo

Thanks for reading! This chat program is meant to be a simple, readable demonstration of how to communicate with Veilid. A real chat program would not look like this:

- A lot of code is duplicated. This was on purpose so that each function would be readable and understandable without having to trace through lots of helper functions.
- The user interface is too simple. If you're halfway through typing a message when your app receives one from the other party, the inbound message will make a mess of your screen.
- The messaging flow is too simple. If you send messages faster than the other party can receive them, some of your messages old will get overwritten by new ones.
- Users have to trade their public keys, and even the chat's DHT key, through another channel like SMS.

But then, the major portions of a real app wouldn't fit on a single screen. This demo just shows how all the moving parts fit together. Your challenge is to take them and build something better!

## Installation

1. Install [poetry](https://python-poetry.org) if you haven't already.
2. Run `poetry install`

## Usage

First, run `veilid-server`. This demo tries to connect to localhost port 5959 by default. You can override that with the `--host` and `--port` arguments.

Create your cryptographic keypair:

```console
$ poetry run chat keygen
Your new public key is: d3aDb3ef
Share it with your friends!
```

_Note: This writes your new private key to a file called `.demokeys`. Don't do that in your app!_

Copy the public key and send it to a friend you want to chat with. Have your friend do the same.

Now, add your friend's public key to your keyring:

```console
$ poetry run chat add-friend MyFriend L0nGkEyStR1ng
```

To start a chat with that friend:

```console
$ poetry run chat start MyFriend
New chat key: VLD0:abcd1234
Give that to your friend!
SEND>
```

Copy that chat key and send it to your chat partner. They can respond to your chat:

```console
$ poetry run chat respond CoolBuddy VLD0:abcd1234
SEND>
```

Now you can send simple text messages back and forth. Your messages are encrypted and transmitted through a distributed hash table (DHT), passed through an open-source, peer-to-peer, mobile-first networked application framework. Neat!

Remember that this simplified program can only receive a message when it's not waiting for you to enter one.

## Sequence diagram

Here's how the program generates keys, uses the Diffie-Hellman (DH) algorithm to calculate shared keys, reads from and writes to the DHT, and uses encryption with nonces to secure messages in the public network.

<!--use:mermaid-->

```mermaid
sequenceDiagram
    # Parties involved:
    actor Alice
    participant Va as Alice's Veilid
    participant Magic
    participant Vb as Bob's Veilid
    actor Bob


    Note over Alice,Bob: Alice and Bob generate keypairs.
    Alice ->> Va: Generate key
    Va ->> Alice: keypair
    Bob ->> Vb: Generate key
    Vb ->> Bob: keypair
    Note over Alice,Bob: Alice and Bob send their public keys to each other.
    Alice -->> Bob: Alice's pubkey (out-of-band)
    Bob -->> Alice: Bob's pubkey (out-of-band)

    Note over Alice,Va: Alice starts a chat by<br/>getting a shared secret.
    Alice ->> Va: cached_dh()<br>(Bob's pubkey, Alice's secret key)
    Va ->> Alice: secret

    Note over Alice,Va: Alice creates a DHT record.
    Alice ->> Va: Create DHT record
    Va ->> Alice: DHT key

    Note over Alice,Bob: Alice sends the DHT record's key to Bob.
    Alice -->> Bob: DHT key (out-of-band)

    Note over Bob,Vb: Bob creates a shared secret.<br/>It will be the same as Alice's.
    Bob ->> Vb: cached_dh()<br>(Alice's pubkey, Bob's secret key)
    Vb ->> Bob: secret

    loop Until done
        Note over Alice,Bob: Alice sends a message to Bob.

        Note over Alice,Va: First, she creates a random nonce.<br/>This is done for each message.
        Alice ->> Va: random_nonce()
        Va ->> Alice: nonce

        Note over Alice,Va: Then she encrypts the message with<br/>the shared key and the nonce.
        Alice ->> Va: encrypt("Message", secret, nonce)
        Va ->> Alice: ciphertext

        Note over Alice,Va: Alice updates the DHT record's "0" subkey<br/>with the nonce plus the encrypted text.
        Alice ->> Va: set_dht_value(0, nonce+ciphertext)

        Note over Va,Vb:  Veilid magic happens!
        Va ->> Magic: Updated DHT key
        Magic ->> Vb: Updated DHT key

        Note over Bob,Vb:  Meanwhile, Bob is polling the DHT key's "0"<br/>subkey, waiting for a message to appear.
        Bob ->> Vb: get_dht_value(0)
        Vb ->> Bob: nonce+ciphertext

        Note over Bob,Vb: Bob decrypts Alice's encrypted message<br/>with the shared secret and the nonce<br/>that was send with the ciphertext.
        Bob ->> Vb: decrypt(ciphertext, secret, nonce)
        Vb->> Bob: "Message"

        Note over Alice,Bob: Bob replies to Alice with a similar process.

        Note over Bob,Vb: First, he asks for a random nonce.<br/>Again, he uses a different nonce each time!
        Bob ->> Vb: random_nonce()
        Vb ->> Bob: nonce

        Note over Bob,Vb: Bob encrypt's his reply with<br/>the shared secret and nonce.
        Bob ->> Vb: encrypt("Reply", secret, nonce)
        Vb ->> Bob: ciphertext

        Note over Bob,Vb:  Although Bob reads from subkey 0,<br/>he writes to subkey 1.
        Bob ->> Vb: set_dht_value(1, nonce+ciphertext)

        Note over Va,Vb: More Veilid magic!
        Vb ->> Magic: Updated DHT key
        Magic ->> Va: Updated DHT key

        Note over Alice,Va: Alice is polling subkey 1 for Alice's<br/>encrypted response.
        Alice ->> Va: get_dht_value(1)
        Va ->> Alice: nonce+ciphertext

        Note over Alice,Va:  Alice decrypts Bob's encrypted reply<br/>with the shared secret and the<br/>nonce accompanying the message.
        Alice ->> Va: decrypt(ciphertext, secret, nonce)
        Va ->> Alice: "Reply"

        Note over Alice,Bob: ...and the repeat until one of them closes the chat.
    end
```
