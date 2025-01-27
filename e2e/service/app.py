from flask import Flask, request, jsonify, Response
from flask_compress import Compress
import urllib.parse
import logging

app = Flask(__name__)
Compress(app)

logging.basicConfig(level=logging.INFO)

@app.route('/echo', methods=['GET', 'POST'])
def echo():
    if request.method == 'POST':
        content_type = request.content_type

        if content_type == 'application/json':
            logging.info(f"JSON {request.data}")
            
            data = request.get_json() 

            return jsonify(data)  
        elif content_type == 'application/x-www-form-urlencoded':
            data = request.form
            
            logging.info(f"FORM {data}")

            response_data = urllib.parse.urlencode(data)
            
            return Response(response_data, content_type='application/x-www-form-urlencoded')
        else:
            logging.info(f"Unsupported Content-Type: {content_type}")
            return jsonify({"error": "Unsupported Content-Type"}), 415 

    else:
        return jsonify({"message": "Send a POST request with JSON or form data."})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)