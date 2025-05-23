class DIDWebResolver:
    @staticmethod
    def resolve(did_web):
        if did_web.startswith("did:web:"):
            # Legge la chiave direttamente dal file
            with open("rsa_pub.key", "r") as f:
                rsa_public_key_pem = f.read()

            did_document = {
                "@context": "https://www.w3.org/ns/did/v1",
                "id": did_web,
                "verificationMethod": [
                    {
                        "id": f"{did_web}#keys-1",
                        "type": "RsaVerificationKey2018",
                        "controller": did_web,
                        "publicKeyPem": rsa_public_key_pem
                    }
                ],
                "authentication": [
                    f"{did_web}#keys-1"
                ],
                "assertionMethod": [
                    f"{did_web}#keys-1"
                ]
            }
            return {
                "document": did_document,
                "publicKey": rsa_public_key_pem
            }
        else:
            raise Exception(f"Formato DID non valido: {did_web}")
