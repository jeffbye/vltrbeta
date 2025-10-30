import json
from datetime import datetime, timedelta
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import dateutil.parser

def handler(event, context):
    try:
        # --- CONFIGURATION ---
        # The private key should be stored as an environment variable in Netlify
        private_key_pem = os.environ.get('VLTR_BETA_PRIVATE_KEY')
        if not private_key_pem:
            return {'statusCode': 500, 'body': 'Server configuration error: Private key not found.'}
            
        # The expiration date for the beta
        expiration_date = datetime(2026, 1, 1) # Year, Month, Day

        # --- TOKEN GENERATION ---
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        
        # Create the data payload
        payload = {
            'issue_date': datetime.utcnow().isoformat(),
            'expiration_date': expiration_date.isoformat(),
            'issuer': 'VLTR Beta Program'
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode()

        # Sign the payload
        signature = private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

        # Combine payload and signature into the final token
        token = {
            'payload': payload,
            'signature': signature.hex()
        }

        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(token)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': f'An error occurred: {str(e)}'
        }