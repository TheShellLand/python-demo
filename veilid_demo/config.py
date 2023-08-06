"""Load and save configuration with Veilid's encrypted table store."""

from typing import Optional

import veilid

KEY_TABLE = "veilid-demo"
SELF_KEY = "self"
FRIEND_PREFIX = "friend:"


async def write_key(conn: veilid.json_api._JsonVeilidAPI, key: str, value: str):
    """Write a single key to the keystore."""

    tdb = await conn.open_table_db(KEY_TABLE, 1)

    async with tdb:
        await tdb.store(key.encode(), value.encode())


async def read_key(conn: veilid.json_api._JsonVeilidAPI, key: str) -> Optional[str]:
    """Read a single key from the keystore."""

    tdb = await conn.open_table_db(KEY_TABLE, 1)

    async with tdb:
        value = await tdb.load(key.encode())
        if value is None:
            return None
        return value.decode()


async def write_self_key(conn: veilid.json_api._JsonVeilidAPI, keypair: veilid.KeyPair):
    """Write our own keypair to the keystore."""

    await write_key(conn, SELF_KEY, str(keypair))


async def read_self_key(conn: veilid.json_api._JsonVeilidAPI) -> Optional[veilid.KeyPair]:
    """Read our own keypair from the keystore."""

    value = await read_key(conn, SELF_KEY)
    if value is None:
        return None
    return veilid.KeyPair(value)


async def friends(conn: veilid.json_api._JsonVeilidAPI) -> list[str]:
    """Return a list of friends registered in the keystore."""

    names = []

    tdb = await conn.open_table_db(KEY_TABLE, 1)

    async with tdb:
        for key_bytes in await tdb.get_keys():
            key = key_bytes.decode()
            if key.startswith(FRIEND_PREFIX):
                names.append(key.removeprefix(FRIEND_PREFIX))

    return sorted(names)


async def write_friend_key(
    conn: veilid.json_api._JsonVeilidAPI, name: str, pubkey: veilid.PublicKey
):
    """Write a friend's public key to the keystore."""

    await write_key(conn, f"{FRIEND_PREFIX}{name}", str(pubkey))


async def read_friend_key(
    conn: veilid.json_api._JsonVeilidAPI, name: str
) -> Optional[veilid.PublicKey]:
    """Read a friend's public key from the keystore."""

    value = await read_key(conn, f"{FRIEND_PREFIX}{name}")
    if value is None:
        return None
    return veilid.PublicKey(value)


async def delete_keystore(conn: veilid.json_api._JsonVeilidAPI):
    """Delete the keystore database."""

    await conn.delete_table_db(KEY_TABLE)
