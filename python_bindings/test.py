import base64

import libpastelid


def main():
    pastel_id_dir = "."
    pastel_signer = libpastelid.PastelSigner(pastel_id_dir)

    message = "test message"
    pastel_id = "jXXmQdZPF5mT6kxPr2Z3HNWsNKoZedC2gFdmwoAQr1e4kD5Jtw6BryZD8fJzZAgc2iAdMsUZ3aGfzE4ccrKkEo"
    password = "passphrase"

    signed_message = pastel_signer.sign_with_pastel_id(message, pastel_id, password)
    print("Signed message:", signed_message)

    verified = pastel_signer.verify_with_pastel_id(message, signed_message, pastel_id)
    print("Verification result:", verified)

    message = base64.b64encode(message.encode('UTF-8')).decode('UTF-8')
    signed_message = pastel_signer.sign_with_pastel_id_base64(message, pastel_id, password)
    print("Signed message:", signed_message)

    verified = pastel_signer.verify_with_pastel_id_base64(message, signed_message, pastel_id)
    print("Verification result:", verified)


if __name__ == "__main__":
    main()
