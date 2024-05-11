
import streamlit as st
import requests
import urllib.parse

def get_query_params():
    query_params = st.query_params
    return query_params

# Function to handle access request response
def handle_response(response):
    if response == "accept":
        st.success("Access request accepted")
        # Implement logic to send response to backend
    elif response == "reject":
        st.warning("Access request rejected")
    else:
        st.error("Invalid response")

# Streamlit app
def main():
    st.title("Decentralized Identity Wallet")

    # Extract verifier data from URL parameters
    query_params = get_query_params()
    verifier_data_str = query_params.get('verifier_data', 'No data provided')+"'"
    verifier_data = urllib.parse.unquote(verifier_data_str)

    if verifier_data:
        try:
            verifier_data_dict = eval(verifier_data)
            st.header("Verifier Details")
            for key, value in verifier_data_dict.items():
                st.write(f"**{key.capitalize()}:** {value}")

            # Prompt for response
            st.header("Response")
            response = st.radio("Do you want to accept this access request?", ("Accept", "Reject"))

            # Handle response
            if st.button("Submit"):
                handle_response(response.lower())
        except SyntaxError:
            st.error("Invalid verifier data format. Please try again.")
    else:
        st.error("Verifier data not found in URL parameters.")

if __name__ == "__main__":
    main()
