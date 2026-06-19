from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
import os
from analyzer import analyze_file
from models import db, AnalysisReport
from utils import allowed_file
from flask_jwt_extended import create_access_token, jwt_required

api = Blueprint('api', __name__)

@api.route('/register', methods=['POST'])
def register():
    # Simple for demo - expand with proper user model
    data = request.json
    # In real: hash password, save user
    token = create_access_token(identity=data.get('username'))
    return jsonify({'token': token})

@api.route('/analyze', methods=['POST'])
@jwt_required()
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    if not allowed_file(file.filename):   
        return jsonify({'error': 'File type not allowed'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(filepath)
    
    try:
        vulns = analyze_file(filepath)
        report = AnalysisReport(filename=filename, vulnerabilities=vulns)
        db.session.add(report)
        db.session.commit()
        
        return jsonify({
            'filename': filename,
            'vulnerabilities': vulns,
            'report_id': report.id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Cleanup (optional: keep for audit)
        if os.path.exists(filepath):
            os.remove(filepath)

    