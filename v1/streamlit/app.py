
import streamlit as st
from cryptography.fernet import Fernet
import json
import uuid

def get_query_params():
    query_params = st.query_params
    return query_params

def read_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def verify_credential(encrypted_credential, key):
    try:
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_credential)
        credential = json.loads(decrypted_data.decode('utf-8')) 
        
        if verify_signature(credential):
            print("Credential is valid and authentic.")
            return credential
        else:
            print("Invalid signature. Credential could be tampered with.")
            return None  
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        return None  

def verify_signature(credential):
    return True

def authenticate(decrypted_credential, wallet):
    id_exists = any(wallet['id'] == subj['id'] for subj in decrypted_credential['credentialSubject'])
    if id_exists:
        return wallet
    else:
        return 'No data'

# Main application
def main():
    st.title('NOTTS ID')

    query_params = get_query_params()
    data = query_params.get('data', 'No data provided')+"'"
    data = bytes(data[2:-1], 'utf-8')
    
    st.header('Select information to share')

    wallet = st.number_input('Enter wallet number:',1)
    useName = st.checkbox("Name")
    useStudentId = st.checkbox("Student ID")
    useCourse = st.checkbox("Course")
    
    file_path_wallet = f"wallets/wallet_{wallet}.json"
    s1 = read_json_file(file_path_wallet)
    
    file_path_key = f"key/key.bin"
    with open(file_path_key, 'rb') as file:
        key = file.read()
    
    if st.button("Process Data"):
        # st.write(data)
        # st.write(key)
        
        decrypted_credential = verify_credential(data, key)
        result = authenticate(decrypted_credential, s1)
        
        all_keys = result.keys()
        keys_to_use = [False, useName, useStudentId, useCourse]
        filtered_dict = {key: value for key, value in result.items() if keys_to_use[list(all_keys).index(key)]}
        
        json_data = json.dumps(filtered_dict)
        
        st.header('Result')
        st.json(json_data)
        
if __name__ == "__main__":
    main()
