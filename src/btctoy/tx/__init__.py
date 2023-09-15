from __future__ import (
    annotations,
)

import json
from io import (
    BytesIO,
)
from pathlib import (
    Path,
)
from typing import (
    BinaryIO,
)

import httpx

from btctoy.codec import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from btctoy.crypto import (
    PrivateKey,
    hash256,
)
from btctoy.script import (
    Script,
)

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3


class Tx:
    def __init__(
        self,
        version: int,
        tx_ins: list[TxIn],
        tx_outs: list[TxOut],
        locktime: int,
        testnet: bool = False,
    ) -> None:
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self) -> str:
        tx_ins = ""
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + "\n"
        tx_outs = ""
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + "\n"
        return "tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}".format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self) -> str:  # noqa: A003
        return self.hash().hex()

    def hash(self) -> bytes:  # noqa: A003
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, s: BinaryIO, testnet: bool = False) -> Tx:

        version = little_endian_to_int(s.read(4))
        
        num_inputs = read_varint(s)
        
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    def serialize(self) -> bytes:
        
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins)) 
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    # tag::source1[]
    def fee(self) -> int:
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum

    # end::source1[]

    def sig_hash(self, input_index: int) -> int:
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_index, tx_in in enumerate(self.tx_ins):
            if tx_index == input_index:
                result += TxIn(
                    tx_in.prev_tx,
                    tx_in.prev_index,
                    tx_in.script_pubkey(self.testnet),
                    tx_in.sequence,
                ).serialize()
            else:
                result += b"\x00"

        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            result += tx_out.serialize()

        result += int_to_little_endian(self.locktime, 4)
        result += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(hash256(result), "big")

    def verify_input(self, input_index: int) -> bool:
        """Returns whether the input has a valid signature"""
        tx_in = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey()
        sig_hash = self.sig_hash(input_index)
        script = tx_in.script_sig + script_pubkey

        return script.evaluate(sig_hash)

    def verify(self) -> bool:
        if self.fee() < 0:  # <1>
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):  # <2>
                return False
        return True


    def sign_input(self, input_index: int, private_key: PrivateKey) -> bool:
        sig_hash = self.sig_hash(input_index)
        der = private_key.sign(sig_hash).der()
        sig = der + SIGHASH_ALL.to_bytes(1, "big")
        sec = private_key.point.sec()
        script_sig = Script([sig, sec])
        self.tx_ins[input_index].script_sig = script_sig
        return self.verify_input(input_index)


class TxIn:
    def __init__(
        self,
        prev_tx: bytes,
        prev_index: int,
        script_sig: Script | None = None,
        sequence: int = 0xFFFFFFFF,
    ) -> None:
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self) -> str:
        return f"{self.prev_tx.hex()}:{self.prev_index}"

    @classmethod
    def parse(cls, s: BinaryIO) -> TxIn:
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet: bool = False) -> Tx:
        return fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet: bool = False) -> int:
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet: bool = False) -> Script:

        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:
    def __init__(self, amount: int, script_pubkey: Script) -> None:
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self) -> str:
        return f"{self.amount}:{self.script_pubkey}"

    @classmethod
    def parse(cls, s: BinaryIO) -> TxOut:
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)

    def serialize(self) -> bytes:
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


cache = {}


def get_url(testnet: bool = False) -> str:
    if testnet:
        return "https://blockstream.info/testnet/api"
    return "https://blockstream.info/api"


def fetch(tx_id: str, testnet: bool = False, fresh: bool = False) -> Tx:
    if fresh or (tx_id not in cache):
        url = f"{get_url(testnet)}/tx/{tx_id}/hex"
        response = httpx.get(url)
        try:
            raw = bytes.fromhex(response.text.strip())
        except ValueError:
            raise ValueError("unexpected response: {}".format(response.text))
        if raw[4] == 0:
            raw = raw[:4] + raw[6:]
            tx = Tx.parse(BytesIO(raw), testnet=testnet)
            tx.locktime = little_endian_to_int(raw[-4:])
        else:
            tx = Tx.parse(BytesIO(raw), testnet=testnet)
        if tx.id() != tx_id:
            raise ValueError("not the same id: {} vs {}".format(tx.id(), tx_id))
        cache[tx_id] = tx
    cache[tx_id].testnet = testnet
    return cache[tx_id]


def load_cache(filepath: Path) -> None:
    disk_cache = json.loads(filepath.read_text(encoding="utf-8"))
    for k, raw_hex in disk_cache.items():
        raw = bytes.fromhex(raw_hex)
        if raw[4] == 0:
            raw = raw[:4] + raw[6:]
            tx = Tx.parse(BytesIO(raw))
            tx.locktime = little_endian_to_int(raw[-4:])
        else:
            tx = Tx.parse(BytesIO(raw))
        cache[k] = tx


def dump_cache(filepath: Path) -> None:
    to_dump = {k: tx.serialize().hex() for k, tx in cache.items()}
    s = json.dumps(to_dump, sort_keys=True, indent=4)
    filepath.write_text(s, encoding="utf-8", newline="\n")
