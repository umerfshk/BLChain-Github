
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import json
import os

# 
class DID:
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key, self.did = self.generate_keys_and_did()
        self.store_did_in_blockchain()
        self.wallet = {}

    # Wallet generation
    def store_vc_in_wallet(self, vc_type, vc):
        self.wallet[vc_type] = vc

    def get_vc_from_wallet(self, vc_type):
        return self.wallet.get(vc_type, None)
    
    # Generate DIDs
    def generate_keys_and_did(self):
        
        # Generate DID - public key pair using RSA encryption algorithm
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Create DID
        did = self.generate_did(public_key_pem)
        
        return private_key, public_key, did

    def generate_did(self, public_key_pem):
        # Generate DID using the public key pem
        return f"did:{self.name}:{hash(public_key_pem)}"
    
    # Storing DIDs on proxy blockchain
    def store_did_in_blockchain(self):
        # Blockchain proxy folder
        blockchain_folder = "../blockchain"
        if not os.path.exists(blockchain_folder):
            os.makedirs(blockchain_folder)

        # Replace so it can be saved as a filename
        filename_safe_did = self.did.replace(":", "_")

        # save DID and public key pair as a json file
        did_filename = os.path.join(blockchain_folder, f"{filename_safe_did}.json")
        with open(did_filename, "w") as file:
            json.dump({"public_key": self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()}, file)

    @staticmethod
    def resolve_did_locally(did):
        # Simulated DID resolution locally from the blockchain folder
        blockchain_folder = "../blockchain"
        if not os.path.exists(blockchain_folder):
            raise FileNotFoundError("Blockchain folder not found.")
        
        # Replace colons with underscores in the DID for filename compatibility
        filename_safe_did = did.replace(":", "_")
        
        # Extract the public key from the corresponding DID 
        did_filename = os.path.join(blockchain_folder, f"{filename_safe_did}.json")
        if not os.path.exists(did_filename):
            return None
        
        with open(did_filename, "r") as file:
            data = json.load(file)
            public_key_pem = data.get("public_key", None)
        
        if public_key_pem:
            return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        else:
            return None
    
    def issue_vc(self, subject_did, data):
        # Resolve the subject's DID to retrieve the public key
        subject_public_key = self.resolve_did_locally(subject_did)
        if not subject_public_key:
            raise ValueError("Failed to resolve subject's DID or retrieve public key.")

        # Issue Verifiable Credential
        # General format of a VC
        vc = {
            "id": f"{self.did}/vc/{datetime.now().isoformat()}",
            "type": ["VerifiableCredential"],
            "issuer": self.did,
            "issuanceDate": datetime.now().isoformat(),
            "credentialSubject": {
                "id": subject_did,
                "data": data
            }
        }
        
        # Encoding VC as bytes
        vc_bytes = json.dumps(vc).encode()
        
        # Sign the VC with the private key
        signature = self.private_key.sign(
            vc_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        vc["signature"] = signature.hex()
        return vc
            
    def respond_to_request(self, requests):
        # Bundles VCs together per the requests
        response = {}
        for request in requests:
            if request in self.wallet:
                response[request] = self.wallet[request]

        return response
    
    def generate_vp(self, requests):
        # Generate a Verifiable Presentation 
        response = self.respond_to_request(requests)

        # Extract VCs from the response
        vcs = list(response.values())

        # Generate a presentation containing the VCs
        presentation = {
            "holder": self.did,
            "verifiable_credentials": vcs,
            "requests": list(response.keys())
        }

        # Serialize the presentation
        presentation_bytes = json.dumps(presentation).encode()

        # Sign the presentation with the private key
        signature = self.private_key.sign(
            presentation_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        presentation["signature"] = signature.hex()

        return presentation

    
    def verify_vp(self, vp):
        # Extract issuer and holder DIDs from the VC within the VP
        vc = vp["verifiable_credentials"][0]  
        issuer_did = vc["issuer"]
        holder_did = vp["holder"]

        # Resolve issuer and holder DIDs to retrieve public keys
        issuer_public_key = self.resolve_did_locally(issuer_did)
        holder_public_key = self.resolve_did_locally(holder_did)

        # Check if public keys are retrieved successfully
        if not issuer_public_key or not holder_public_key:
            print("Failed to resolve DIDs or retrieve public keys.")
            return None

        # Extract signature from VCs
        vc_signature = bytes.fromhex(vc["signature"])

        # Encode VC
        vc_copy = vc.copy()
        vc_copy.pop("signature")
        vc_bytes = json.dumps(vc_copy).encode()

        # Verify the issuer's signature using the issuer's public key
        try:
            issuer_public_key.verify(
                vc_signature,
                vc_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Issuer authenticity verified.")
        except Exception as e:
            print("Issuer verification failed:", e)
            return None

        # Extract signature from the VP
        vp_signature = bytes.fromhex(vp["signature"])

        # Encode VP
        vp_copy = vp.copy()
        vp_copy.pop("signature")
        vp_bytes = json.dumps(vp_copy).encode()

        # Verify the holder's signature using the holder's public key
        try:
            holder_public_key.verify(
                vp_signature,
                vp_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Holder authenticity verified.")
        except Exception as e:
            print("Holder verification failed:", e)
            return None

        # Extract 'credentialSubject' contained in the VC
        credential_subject = vc.get("credentialSubject", None)
        if credential_subject:
            print("Credential subject extracted successfully.")
            return credential_subject
        else:
            print("No credential subject found.")
            return None
