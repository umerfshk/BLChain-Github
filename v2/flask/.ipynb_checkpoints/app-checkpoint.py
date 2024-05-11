
from flask import Flask, send_file
import qrcode

app = Flask(__name__)

# Dummy verifier data
verifier_data = {
    "name": "Example Corp",
    "purpose": "Access request for authentication",
    "additional_info": "Additional information about the request"
}

# Endpoint for the verifier to request access
@app.route("/request-access")
def request_access():
    # Generate QR code containing verifier data
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(str(verifier_data))
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_path = "verifier_qr.png"
    img.save(img_path)  # Save QR code as an image file

    return send_file(img_path, mimetype='image/png')

if __name__ == "__main__":
    app.run(debug=True)
