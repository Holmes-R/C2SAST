# backend/app.py
from flask import Flask, request, jsonify
from config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)
Config.init_app(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400
    # For now just return a fake token
    token = f"fake-token-{username}"
    return jsonify({'token': token})

@app.route('/api/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Only {Config.ALLOWED_EXTENSIONS} allowed'}), 400
    
    # Save file temporarily
    filepath = os.path.join(Config.UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    try:
        from analyzer import analyze_file
        vulns = analyze_file(filepath)
        result = {
            "filename": file.filename,
            "vulnerabilities": vulns
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Optional: clean up
        if os.path.exists(filepath):
            os.remove(filepath)

if __name__ == '__main__':
    app.run(debug=True, port=5000)