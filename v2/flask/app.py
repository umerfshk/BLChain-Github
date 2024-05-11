from flask import Flask, jsonify, request, send_file
from did import DID
import qrcode

app = Flask(__name__)
vendor_did = DID('vendor')

@app.route('/request-access')
def generate_qr():
    # Generate the data string to be encoded in the QR code
    address="http://10.132.198.247:8501"
    did = f"{vendor_did.did}".replace(":", "_")
    qr_data = f'{address}/?did={did}'

    # Create QR code
    qr = qrcode.QRCode(
        version=1, 
        error_correction=qrcode.constants.ERROR_CORRECT_L, 
        box_size=10, 
        border=4)
    qr.add_data(qr_data)
    qr.make(fit=True)

    # Generate QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    img_path = "verifier_qr.png"
    img.save(img_path)  # Save QR code as an image file

    return send_file(img_path, mimetype='image/png')

@app.route('/verify_vp', methods=['POST'])
def verify_vp():
    data = request.json
    response = data.get('response')

    if response == 'fail':
        # Logic for handling failed response
        return jsonify({"message": "Holder rejected access"}), 200
    elif response:
        information = vendor_did.verify_vp(response)
        print(information)
        return jsonify({"message": information}), 200
    else:
        return jsonify({"error": "Invalid response"}), 400
    
if __name__ == '__main__':
    app.run(debug=True)

if __name__ == "__main__":
    app.run(debug=True)
