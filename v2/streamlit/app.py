
import streamlit as st
import requests
import socket
import urllib.parse
from did import DID

# Write the network URL 
ip = socket.gethostbyname(socket.gethostname())
port = 8501  # The port you choose to run Streamlit on
with open("../streamlit_url.txt", "w") as f:
    f.write(f"http://{ip}:{port}")

def initialize_did():
        
    student = DID("student")
    uni = DID('university')
    vc_data = {"name": "Bob", "age": 30}
    vc = uni.issue_vc(student.did, vc_data)
    student.store_vc_in_wallet('degree', vc)
    return student

def get_query_params():
    query_params = st.query_params
    return query_params

# Function to handle access request response
def handle_response(response):
    if response == "Accept":
        # st.success("Access request accepted")
        # Implement logic to send response to backend
        
        info_needed = ["degree"]
        proof = st.session_state.student.generate_vp(info_needed)
        
        response_data = {'response': proof}
        
    elif response == "Cancel":
        # st.warning("Access request canceled")
        response_data = {'response': 'fail'}
    else:
        st.error("Invalid response")
        return
    
    # Send POST request to server
    try:
        response = requests.post('http://127.0.0.1:5000/verify_vp', json=response_data)
        if response.status_code == 200:
            # st.success("Response sent successfully")
            if response_data['response'] == 'fail':
                st.warning("Access request canceled by holder")
            else:
                st.success("Verification success")
                data = response.json()
                information = data['message']
                st.json(information)
        else:
            st.error("Failed to send response to server")
    except requests.exceptions.ConnectionError:
        st.error("Failed to connect to the server")


# Streamlit app
def main():
    st.title("Decentralized Identity Wallet")

    # Initialize DID only once
    if 'student' not in st.session_state:
        st.session_state.student = initialize_did()

    # Extract verifier data from URL parameters
    query_params = get_query_params()
    did_str = query_params.get('did', 'No data provided')
    did = urllib.parse.unquote(did_str)
    answer = st.session_state.student.resolve_did_locally(did)

    if answer:
        st.write("Verifiable credential request received from:")
        st.write(f"DID: {did}")
        st.write("Verifier: Vendor")
        st.write("Requested Credential: Degree")

        # Buttons for response
        response = st.radio("Do you want to accept or cancel the request?", ("Accept", "Cancel"))
        if st.button("Submit"):
            handle_response(response)

if __name__ == "__main__":
    main()
