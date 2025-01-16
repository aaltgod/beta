from flask import Flask, request, jsonify, Response
from flask_compress import Compress
import urllib.parse

app = Flask(__name__)
Compress(app)

@app.route('/echo', methods=['GET', 'POST'])
def echo():
    print(request.data, request.form)
    
    if request.method == 'POST':
        content_type = request.content_type

        if content_type == 'application/json':
            print("JSON ", request.data)
            
            data = request.get_json() 
            return jsonify(data)  
        elif content_type == 'application/x-www-form-urlencoded':
            data = request.form
            
            print("FORM ", data)

            response_data = urllib.parse.urlencode(data)
            
            return Response(response_data, content_type='application/x-www-form-urlencoded')
        else:
            return jsonify({"error": "Unsupported Content-Type"}), 415 

    else:
        return jsonify({"message": "Send a POST request with JSON or form data."})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)