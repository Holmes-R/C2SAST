from flask import Flask, request , jsonify
import os 
from flask_sqlalchemy import SQLAlchemy
from .backend.models import db ,User
app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

# db = SQLAlchemy(app)

@app.route('/register',methods=['POST'])
def registerUser():
    data = request.get_json()

    if not data:
        return jsonify({'message':'No input data provided'}),400
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if len(username) < 3 or len(username) > 80:
        return jsonify({"error": "Username must be between 3 and 80 characters"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if username is None or password is None:
        return {'message':'Username and password required'},400
    
    if User.query.filter_by(username=username).first() is not None:
        return {'message':'User already exists'},400
    
    user = User(username=username,password=password)


if __name__ == '__main__':
    db.create_all()
    app.run()