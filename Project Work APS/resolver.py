
class DIDWebResolver:
    @staticmethod
    def resolve(did_web):
        """
        Risolve un DID Web e recupera il documento DID associato

        Args:
            did_web (str): Il DID Web da risolvere

        Returns:
            dict: Il documento DID

        Raises:
            Exception: Se non è possibile risolvere il DID
        """
        # In un sistema reale, qui si farebbe una richiesta HTTP per ottenere
        # il documento DID dall'URL corrispondente al DID Web

        # Per questa simulazione, restituiamo un documento DID di esempio
        if did_web.startswith("did:web:"):
            # Documento DID simulato
            did_document = {
                "@context": "https://www.w3.org/ns/did/v1",
                "id": did_web,
                "verificationMethod": [
                    {
                        "id": f"{did_web}#keys-1",
                        "type": "Ed25519VerificationKey2020",
                        "controller": did_web,
                        "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                    }
                ],
                "authentication": [
                    f"{did_web}#keys-1"
                ],
                "assertionMethod": [
                    f"{did_web}#keys-1"
                ]
            }
            return did_document
        else:
            raise Exception(f"Formato DID non valido: {did_web}")