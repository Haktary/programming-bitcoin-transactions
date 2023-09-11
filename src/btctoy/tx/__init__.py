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
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()

    def hash(self) -> bytes:  # noqa: A003
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, s: BinaryIO, testnet: bool = False) -> Tx:
        """Takes a byte stream and parses the transaction at the start
        return a Tx object
        """
        # s.read(n) will return n bytes
        # version is an integer in 4 bytes, little-endian
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # parse num_inputs number of TxIns
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # parse num_outputs number of TxOuts
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is an integer in 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    def serialize(self) -> bytes:
        """Returns the byte serialization of the transaction"""
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of outputs
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
        """Returns the fee of this transaction in satoshi"""
        input_sum, output_sum = 0, 0
        # TODO Implémenter la fonction
        # - boucler sur les inputs, additionner leur valeur
        # - boucler sur les outputs, additionner leur valeur
        # - return la difference entre input_sum et output_sum
        pass

    # end::source1[]

    def sig_hash(self, input_index: int) -> int:
        """Returns the integer representation of the hash that needs to get
        signed for index input_index"""
        # TODO implémenter la fonction - celle ci va globalement faire la même chose que serialize sauf qu'on va vider tous les ScriptSig
        # et uniquement remplacer celui de input_index par le ScriptPubKey de l'UTXO pointée
        # vous pouvez donc copier-coller le contenu de serialize et l'adapter selon les instructions du livre "Programming Bitcoin" ci-dessous:

        # start the serialization with version
        # use int_to_little_endian in 4 bytes
        # add how many inputs there are using encode_varint
        # loop through each input using enumerate, so we have the input index
        # if the input index is the one we're signing
        # the previous tx's ScriptPubkey is the ScriptSig
        # Otherwise, the ScriptSig is empty
        # add the serialization of the input with the ScriptSig we want
        # add how many outputs there are using encode_varint
        # add the serialization of each output
        # add the locktime using int_to_little_endian in 4 bytes
        # add SIGHASH_ALL using int_to_little_endian in 4 bytes
        # hash256 the serialization
        # convert the result to an integer using int.from_bytes(x, 'big')
        return int.from_bytes(hash256(result), "big")

    def verify_input(self, input_index: int) -> bool:
        """Returns whether the input has a valid signature"""
        # TODO implémenter la fonction vérifiant une input
        # pour cela on calcule le sig_hash de l'input en question
        # on calcule le script de l'input en question (ScriptSig + ScriptPubKey)
        # et on evalue le script sur le sig_hash
        pass

    # tag::source2[]
    def verify(self) -> bool:
        """Verify this transaction"""
        # TODO implémenter la fonction
        # 1. Les fees doivent être positif ou nul
        # 2. Chaque input doit être valide
        pass

    # end::source2[]

    def sign_input(self, input_index: int, private_key: PrivateKey) -> bool:
        # TODO implémenter la fonction en suivant les instructions:
        # get the signature hash (z)
        # get der signature of z from private key
        # append the SIGHASH_ALL to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        # calculate the sec
        # initialize a new script with [sig, sec] as the cmds
        # change input's script_sig to new script
        # return whether sig is valid using self.verify_input
        pass


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
        """Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        """
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is an integer in 4 bytes, little endian
        prev_index = little_endian_to_int(s.read(4))
        # use Script.parse to get the ScriptSig
        script_sig = Script.parse(s)
        # sequence is an integer in 4 bytes, little-endian
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        """Returns the byte serialization of the transaction input"""
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet: bool = False) -> Tx:
        return fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet: bool = False) -> int:
        """Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        """
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the amount property
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet: bool = False) -> Script:
        """Get the ScriptPubKey by looking up the tx hash
        Returns a Script object
        """
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the script_pubkey property
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:
    def __init__(self, amount: int, script_pubkey: Script) -> None:
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self) -> str:
        return f"{self.amount}:{self.script_pubkey}"

    @classmethod
    def parse(cls, s: BinaryIO) -> TxOut:
        """Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        """
        # amount is an integer in 8 bytes, little endian
        amount = little_endian_to_int(s.read(8))
        # use Script.parse to get the ScriptPubKey
        script_pubkey = Script.parse(s)
        # return an instance of the class (see __init__ for args)
        return cls(amount, script_pubkey)

    def serialize(self) -> bytes:
        """Returns the byte serialization of the transaction output"""
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


# Fetching transactions from external provider:

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
        # make sure the tx we got matches to the hash we requested
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
