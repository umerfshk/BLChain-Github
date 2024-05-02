
import streamlit as st
from cryptography.fernet import Fernet
import json
import uuid

# Function to extract query parameters
def get_query_params():
    query_params = st.query_params
    return query_params

# Function to read JSON file and parse as dictionary
def read_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

# Authentication process
def verify_credential(encrypted_credential, key):
    try:
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_credential)
        credential = json.loads(decrypted_data.decode('utf-8'))  # Decode the bytes object to string
        
        if verify_signature(credential):
            print("Credential is valid and authentic.")
            return credential
        else:
            print("Invalid signature. Credential could be tampered with.")
            return None  # Explicitly return None when verification fails
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        return None  # Explicitly return None when an exception occurs

def verify_signature(credential):
    # Dummy function for signature verification
    # In real implementation, this function should check the digital signature properly
    return True  # Assuming signature is always valid for demonstration

def authenticate(decrypted_credential, wallet):
    id_exists = any(wallet['id'] == subj['id'] for subj in decrypted_credential['credentialSubject'])
    if id_exists:
        # print('Authentication Success\n------------------------------------------\n')
        # return json.dumps(wallet, indent=2)
        return wallet
    else:
        # print('Authentication Error')
        return 'No data'

# Main application
def main():
    st.title('QR Code Decoder')
    
    # Get the data from the URL query parameter
    query_params = get_query_params()
    data = query_params.get('data', 'No data provided')+"'"
    data = bytes(data[2:-1], 'utf-8')
    
    # Display the decoded data
    st.header('Decoded Data')
    
    # Allow user to input a key
    key = st.text_input("Enter Key:", "")
    key = bytes(key, 'utf-8')
    
    wallet = st.number_input('Enter wallet number:',1)
    
    # Read JSON file and parse as dictionary
    file_path = f"wallets/wallet{wallet}.json"
    s1 = read_json_file(file_path)
    
    # Process the data with the key
    if st.button("Process Data"):
        # st.write(data)
        # st.write(key)
        
        decrypted_credential = verify_credential(data, key)
        result = authenticate(decrypted_credential, s1)
        st.json(result)
        


if __name__ == "__main__":
    main()
