#!/usr/bin/env python

"""A simple chat server using Veilid's DHT."""

import argparse
import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from veilid_demo import config

import veilid

QUIT = "QUIT"
NONCE_LENGTH = 24


async def noop_callback(*args, **kwargs):
    """In the real world, we'd use this to process interesting incoming events."""

    return


async def async_input(prompt: str = "") -> str:
    """A non-blocking version of input()."""

    with ThreadPoolExecutor(1, "async_input") as executor:
        return await asyncio.get_event_loop().run_in_executor(executor, input, prompt)


async def sender(
    router: veilid.api.RoutingContext,
    crypto_system: veilid.CryptoSystem,
    key: veilid.TypedKey,
    secret: veilid.SharedSecret,
    send_subkey: veilid.ValueSubkey,
):
    """Read input and write it to the DHT."""

    async def encrypt(cleartext: str) -> bytes:
        """Encrypt the message with the shared secret and a random nonce."""

        nonce = await crypto_system.random_nonce()
        encrypted = await crypto_system.crypt_no_auth(cleartext.encode(), nonce, secret)
        return nonce.to_bytes() + encrypted

    async def send(cleartext: str):
        """Write the encrypted version of the text to the DHT."""

        await router.set_dht_value(key, send_subkey, await encrypt(cleartext))

    # Prime the pumps. Especially when starting the conversation, this
    # causes the DHT key to propagate to the network.
    await send("Hello from the world!")

    while True:
        try:
            msg = await async_input("SEND> ")
        except EOFError:
            # Cat got your tongue? Hang up.
            print("Closing the chat.")
            await send(QUIT)
            return

        # Write the input message to the DHT key.
        await send(msg)


async def receiver(
    router: veilid.api.RoutingContext,
    crypto_system: veilid.CryptoSystem,
    key: veilid.TypedKey,
    secret: veilid.SharedSecret,
    recv_subkey: veilid.ValueSubkey,
):
    """Wait for new data from the DHT and write it to the screen."""

    async def decrypt(payload: bytes) -> str:
        """Decrypt the payload with the shared secret and the payload's nonce."""

        nonce = veilid.Nonce.from_bytes(payload[:NONCE_LENGTH])
        encrypted = payload[NONCE_LENGTH:]
        cleartext = await crypto_system.crypt_no_auth(encrypted, nonce, secret)
        return cleartext.decode()

    last_seq = -1
    while True:
        # In the real world, don't do this. People may tease you for it.
        # This is meant to be easy to understand for demonstration
        # purposes, not a great pattern. Instead, you'd want to use the
        # callback function to handle events asynchronously.

        # Try to get an updated version of the receiving subkey.
        resp = await router.get_dht_value(key, recv_subkey, True)
        if resp is None:
            continue

        # If the other party hasn't sent a newer message, try again.
        if resp.seq == last_seq:
            continue

        msg = await decrypt(resp.data)
        if msg == QUIT:
            print("Other end closed the chat.")
            return

        print(f"\nRECV< {msg}")
        last_seq = resp.seq


async def start(host: str, port: int, name: str):
    """Begin a conversation with a friend."""

    conn = await veilid.json_api_connect(host, port, noop_callback)

    my_keypair = await config.read_self_key(conn)
    if my_keypair is None:
        print("Use 'keygen' to generate a keypair first.")
        sys.exit(1)

    their_key = await config.read_friend_key(conn, name)
    if their_key is None:
        print("Add their key with 'add-friend' first.")
        sys.exit(1)

    members = [
        veilid.DHTSchemaSMPLMember(my_keypair.key(), 1),
        veilid.DHTSchemaSMPLMember(their_key, 1),
    ]

    router = await (await conn.new_routing_context()).with_privacy()
    crypto_system = await conn.get_crypto_system(veilid.CryptoKind.CRYPTO_KIND_VLD0)
    async with crypto_system, router:
        secret = await crypto_system.cached_dh(their_key, my_keypair.secret())

        record = await router.create_dht_record(veilid.DHTSchema.smpl(0, members))
        print(f"New chat key: {record.key}")
        print("Give that to your friend!")

        # Close this key first. We'll reopen it for writing with our saved key.
        await router.close_dht_record(record.key)

        await router.open_dht_record(record.key, my_keypair)

        # The party initiating the chat writes to subkey 0 and reads from subkey 1.
        send_task = asyncio.create_task(sender(router, crypto_system, record.key, secret, 0))
        recv_task = asyncio.create_task(receiver(router, crypto_system, record.key, secret, 1))

        try:
            await asyncio.wait([send_task, recv_task], return_when=asyncio.FIRST_COMPLETED)
        finally:
            await router.close_dht_record(record.key)
            await router.delete_dht_record(record.key)

        recv_task.cancel()
        send_task.cancel()


async def respond(host: str, port: int, name: str, key: str):
    """Reply to a friend's chat."""

    conn = await veilid.json_api_connect(host, port, noop_callback)

    my_keypair = await config.read_self_key(conn)
    if my_keypair is None:
        print("Use 'keygen' to generate a keypair first.")
        sys.exit(1)

    their_key = await config.read_friend_key(conn, name)
    if their_key is None:
        print("Add their key with 'add-friend' first.")
        sys.exit(1)

    router = await (await conn.new_routing_context()).with_privacy()
    crypto_system = await conn.get_crypto_system(veilid.CryptoKind.CRYPTO_KIND_VLD0)
    async with crypto_system, router:
        secret = await crypto_system.cached_dh(their_key, my_keypair.secret())

        await router.open_dht_record(key, my_keypair)

        # The party responding to the chat writes to subkey 1 and reads from subkey 0.
        send_task = asyncio.create_task(sender(router, crypto_system, key, secret, 1))
        recv_task = asyncio.create_task(receiver(router, crypto_system, key, secret, 0))

        try:
            # Write to the 1st subkey and read from the 2nd.
            await asyncio.wait([send_task, recv_task], return_when=asyncio.FIRST_COMPLETED)
        finally:
            await router.close_dht_record(key)
            await router.delete_dht_record(key)

        recv_task.cancel()
        send_task.cancel()


async def keygen(host: str, port: int):
    """Generate a keypair."""

    conn = await veilid.json_api_connect(host, port, noop_callback)

    if await config.read_self_key(conn):
        print("You already have a keypair.")
        sys.exit(1)

    crypto_system = await conn.get_crypto_system(veilid.CryptoKind.CRYPTO_KIND_VLD0)
    async with crypto_system:
        my_keypair = await crypto_system.generate_key_pair()

    await config.write_self_key(conn, my_keypair)

    print(f"Your new public key is: {my_keypair.key()}")
    print("Share it with your friends!")


async def delete_keystore(host: str, port: int):
    """Delete the keystore database."""

    conn = await veilid.json_api_connect(host, port, noop_callback)

    await config.delete_keystore(conn)


async def dump_keystore(host: str, port: int):
    """Print the contents of the keystore database."""

    conn = await veilid.json_api_connect(host, port, noop_callback)

    my_keypair = await config.read_self_key(conn)
    if my_keypair:
        print("Own keypair:")
        print("    Public: ", my_keypair.key())
        print("    Private: ", my_keypair.secret())
    else:
        print("Own keypair: <unset>")

    print()
    print("Friends:")
    friends = await config.friends(conn)
    if friends:
        for name in friends:
            pubkey = await config.read_friend_key(conn, name)
            print(f"    {name}: {pubkey}")
    else:
        print("    <unset>")


async def add_friend(host: str, port: int, name: str, pubkey: str):
    """Add a friend's public key."""

    conn = await veilid.json_api_connect(host, port, noop_callback)

    await config.write_friend_key(conn, name, veilid.PublicKey(pubkey))


async def clean(host: str, port: int, key: str):
    """Delete a DHT key."""

    conn = await veilid.json_api_connect(host, port, noop_callback)

    router = await (await conn.new_routing_context()).with_privacy()
    async with router:
        await router.close_dht_record(key)
        await router.delete_dht_record(key)


def handle_command_line(arglist: Optional[list[str]] = None):
    """Process the command line.

    This isn't the interesting part."""

    if arglist is None:
        arglist = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Veilid chat demonstration")
    parser.add_argument("--host", default="localhost", help="Address of the Veilid server host.")
    parser.add_argument("--port", type=int, default=5959, help="Port of the Veilid server.")

    subparsers = parser.add_subparsers(required=True)

    cmd_start = subparsers.add_parser("start", help=start.__doc__)
    cmd_start.add_argument("name", help="Your friend's name")
    cmd_start.set_defaults(func=start)

    cmd_respond = subparsers.add_parser("respond", help=respond.__doc__)
    cmd_respond.add_argument("name", help="Your friend's name")
    cmd_respond.add_argument("key", help="The chat's DHT key")
    cmd_respond.set_defaults(func=respond)

    cmd_keygen = subparsers.add_parser("keygen", help=keygen.__doc__)
    cmd_keygen.set_defaults(func=keygen)

    cmd_delete_keystore = subparsers.add_parser("delete-keystore", help=delete_keystore.__doc__)
    cmd_delete_keystore.set_defaults(func=delete_keystore)

    cmd_dump_keystore = subparsers.add_parser("dump-keystore", help=dump_keystore.__doc__)
    cmd_dump_keystore.set_defaults(func=dump_keystore)

    cmd_add_friend = subparsers.add_parser("add-friend", help=add_friend.__doc__)
    cmd_add_friend.add_argument("name", help="Your friend's name")
    cmd_add_friend.add_argument("pubkey", help="Your friend's public key")
    cmd_add_friend.set_defaults(func=add_friend)

    cmd_clean = subparsers.add_parser("clean", help=clean.__doc__)
    cmd_clean.add_argument("key", help="DHT key to delete")
    cmd_clean.set_defaults(func=clean)

    args = parser.parse_args(arglist)
    kwargs = args.__dict__
    func = kwargs.pop("func")

    asyncio.run(func(**kwargs))


if __name__ == "__main__":
    handle_command_line()
