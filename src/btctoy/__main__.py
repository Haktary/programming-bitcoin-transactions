from dataclasses import (
    dataclass,
)
from pathlib import (
    Path,
)

import click
import typer
from dotenv import (
    load_dotenv,
)

from btctoy import (
    __version__,
)
from btctoy.codec import (
    decode_base58_checksum,
    little_endian_to_int,
)
from btctoy.crypto import (
    PrivateKey,
    hash256,
)
from btctoy.script import (
    p2pkh_script,
)
from btctoy.tx import (
    Tx,
    TxIn,
    TxOut,
)
from btctoy.utils.cli import (
    ENVVAR_PREFIX,
    LogLevelOption,
    VersionOption,
)
from btctoy.utils.logging import (
    LogLevel,
    get_logger,
)

app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=True,
)

logger = get_logger()

ENVVAR_SECRET_PASSPHRASE = f"{ENVVAR_PREFIX}_SECRET_PASSPHRASE"

load_dotenv(".env")  # shared environment configuration
load_dotenv(Path(".local") / ".env")  # private environment configuration


@app.callback()
def cli_callback(
    ctx: click.Context,
    log_level: str = LogLevelOption(),
    version: bool = VersionOption(__version__),
    secret_passphrase: str = typer.Option(
        default=None,
        envvar=ENVVAR_SECRET_PASSPHRASE,
    ),
) -> None:
    ctx.obj = Config(log_level=LogLevel(log_level), secret_passphrase=secret_passphrase)


@dataclass
class Config:
    log_level: LogLevel
    secret_passphrase: str | None


def get_config(ctx: click.Context) -> Config:
    return ctx.obj


@app.command()
def about() -> None:
    typer.echo(f"btctoy CLI version {__version__}")


def make_private_key(passphrase: str) -> PrivateKey:
    # TODO implementation
    # 1. On applique hash256 sur passphrase.encode() (hash256 prend un paramètre un tableau d'octets, pas une str)
    # 2. On applique little_endian_to_int() sur le résultat
    # 3. On construit un objet de type PrivateKey et on le return
    ...


@app.command()
def generate(
    ctx: click.Context,
) -> None:
    config = get_config(ctx)
    if config.secret_passphrase is None:
        typer.echo(
            f"Please provide a passphrase with --secret-passphrase or env var ${ENVVAR_SECRET_PASSPHRASE}"
        )
        raise typer.Abort()

    pk = make_private_key(config.secret_passphrase)

    typer.echo(f"Passphrase {config.secret_passphrase}")
    typer.echo(f"Private Key: {pk.secret}")
    typer.echo(f"Public Key: {pk.point}")
    typer.echo(f"Mainnet address: {pk.point.address(testnet=False)}")
    typer.echo(f"Testnet address: {pk.point.address(testnet=True)}")


@app.command()
def send(
    ctx: click.Context,
    input_tx_id: str,
    input_utxo_index: int,
) -> None:
    config = get_config(ctx)
    if config.secret_passphrase is None:
        typer.echo(
            f"Please provide a passphrase with --secret-passphrase or env var ${ENVVAR_SECRET_PASSPHRASE}"
        )
        raise typer.Abort()

    pk = make_private_key(config.secret_passphrase)

    target_address = "mpLwne78PN7KyQgSvApvu4yTXFc3dn74xL"

    # TODO implementation
    # 1. stocker dans une variable target_h160 le hash160 de l'addresse cible en utilisant decode_base58_checksum()
    # 2. stocker dans une variable my_h160 le hash160 de pk en utilisant pk.point.hash160(compressed=True)
    # 3. stocker dans prev_tx_id la conversion de input_tx_id en bytes calculée avec avec bytes.fromhex
    # 4. stocker dans tx_in une instance de TxIn initialisé avec prev_tx_id et input_utxo_index
    # 5. calculer dans prev_utxo_value la valeur de la tx_in avec la methode value() évaluée sur le testnet

    target_amount = int(0.6 * prev_utxo_value)
    fee = 1500  # 1500 sats, à adapter selon les besoins (aller plus vite, ou pas assez d'argent)

    # 6. stocker dans tx_out_0 une instance de TxOut initialisée avec target_amount et un script p2pkh payant target_address (p2pkh_script(target_h160))
    # 7. stocker dans tx_out_1 une instance de TxOut initialisée avec prev_utxo_value - target_amount - fee et rendant la monnaie (p2pkh_script(my_h160))
    # 8. stocker dans tx une instance de Tx ayant pour version 1, les inputs qu'on a défini, les outputs qu'on a défini, un locktime à 0 et sur le testnet
    # 9. signer l'input 0 de tx avec la clef privée

    # On affiche la transaction encodée en hexadecimal et on l'envoie sur https://live.blockcypher.com/btc/pushtx/
    typer.echo(tx.serialize().hex())


if __name__ == "__main__":
    app()
