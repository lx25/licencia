"""Script local de un solo uso para generar el par de llaves RSA de 2048 bits."""

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(
    private_path: Path = Path("private_key.pem"),
    public_path: Path = Path("public_key.pem"),
    force: bool = False,
) -> None:
    """Genera un par de llaves RSA-2048 en formato PEM (PKCS8 / SubjectPublicKeyInfo)."""
    if not force and (private_path.exists() or public_path.exists()):
        raise FileExistsError(
            "Ya existen archivos de llaves en el directorio actual. "
            "Usa --force si realmente deseas sobrescribirlos."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Genera un par de llaves RSA de 2048 bits (private_key.pem y public_key.pem)."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Sobrescribe private_key.pem y public_key.pem si ya existen.",
    )
    args = parser.parse_args()

    private_path = Path("private_key.pem")
    public_path = Path("public_key.pem")

    generate_rsa_keypair(private_path=private_path, public_path=public_path, force=args.force)

    print("Par de llaves RSA-2048 generado correctamente:")
    print(f" - Privada: {private_path.resolve()} (MANTENER SECRETA, usar en env PRIVATE_KEY_PEM)")
    print(f" - Publica: {public_path.resolve()} (distribuir con tus clientes POS)")


if __name__ == "__main__":
    main()
