import base64

import libpastelid


def main():
    pastel_id_dir = "."
    pastel_signer = libpastelid.PastelSigner(pastel_id_dir)

    message = "test message"
    pastel_id = "jXXmQdZPF5mT6kxPr2Z3HNWsNKoZedC2gFdmwoAQr1e4kD5Jtw6BryZD8fJzZAgc2iAdMsUZ3aGfzE4ccrKkEo"
    password = "passphrase"

    signed_message1 = pastel_signer.sign_with_pastel_id(message, pastel_id, password)
    print("Signed message with pastel_signer:", signed_message1)

    verified = pastel_signer.verify_with_pastel_id(message, signed_message1, pastel_id)
    print("Verification result:", verified)

    message_64 = base64.b64encode(message.encode('UTF-8')).decode('UTF-8')
    signed_message1_64 = pastel_signer.sign_with_pastel_id_base64(message_64, pastel_id, password)
    print("Signed base64 message with pastel_signer:", signed_message1_64)

    verified = pastel_signer.verify_with_pastel_id_base64(message_64, signed_message1_64, pastel_id)
    print("Verification result:", verified)

    pastel_id = pastel_signer.get_pastelid(pastel_id, password)
    signed_message2 = pastel_id.sign(message)
    print("Signed message with pastelid.sign:", signed_message2)

    verified = pastel_id.verify(message, signed_message2)
    print("Verification result:", verified)

    message2_64 = base64.b64encode(message.encode('UTF-8')).decode('UTF-8')
    signed_message2_64 = pastel_id.sign_base64(message2_64)
    print("Signed base64 message with pastelid.sign:", signed_message2_64)

    verified = pastel_id.verify_base64(message2_64, signed_message2_64)
    print("Verification result:", verified)


if __name__ == "__main__":
    main()
