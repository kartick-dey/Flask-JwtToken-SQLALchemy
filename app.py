from flask import Flask, request, jsonify, make_response
import dotenv
import os
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
db_username = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host= os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_name = os.getenv('DB_NAME')

app.config['SECRET_KEY'] = os.getenv('APP_SECRETE_KEY')
# db URI -- dialect+driver://username:password@host:port/database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://{}:{}@{}:{}/{}'.format(db_username, db_password, db_host, db_port, db_name)

db = SQLAlchemy(app)

class User(db.Model):
    """User Model"""
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(64), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    """Todo Model"""
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255))
    conplete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    if not current_user.admin:
        return jsonify({"message": "Can not perform that function"})
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({"users": output}), 200

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_user_by_id(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"}), 202

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin
    return jsonify({"user": user_data}), 200

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password = hashed_password, admin=data['admin'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "new user created!"}), 201

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def update_user(current_user,public_id):
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password = hashed_password, admin=data['admin'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "update successfully!"}), 201

    user.name = data['name']
    user.password = hashed_password
    user.admin = data['admin']
    db.session.commit()
    return jsonify({"message": "update successfully!"}), 202

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user_by_id(current_user,public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"}), 200
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message":'user has been deleted!'}), 200

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({"message": 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="login required"'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Invalid username', 401, {'WWW-Authenticate': 'Basic realm="login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'], algorithm= 'HS256')

        return jsonify({"token": token.decode('UTF-8')})

    return make_response('Invalid password', 401, {'WWW-Authenticate': 'Basic realm="login required"'})


if __name__ == '__main__':
    app.run(debug=True)