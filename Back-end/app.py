from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

db.create_all()

@app.route('/teacher-signup', methods=['POST'])
def teacher_signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not name or not email or not password or not confirm_password:
        return jsonify({'error': 'All fields are required.'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match.'}), 400

    if Teacher.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered.'}), 400

    hashed_password = generate_password_hash(password)
    new_teacher = Teacher(name=name, email=email, password_hash=hashed_password)
    db.session.add(new_teacher)
    db.session.commit()

    return jsonify({'message': 'Teacher account created successfully.'}), 201

@app.route('/student-signup', methods=['POST'])
def student_signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not name or not email or not password or not confirm_password:
        return jsonify({'error': 'All fields are required.'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match.'}), 400

    if Student.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered.'}), 400

    hashed_password = generate_password_hash(password)
    new_student = Student(name=name, email=email, password_hash=hashed_password)
    db.session.add(new_student)
    db.session.commit()

    return jsonify({'message': 'Student account created successfully.'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Check if the user is a teacher
    user = Teacher.query.filter_by(email=email).first()
    if not user:
        # Check if the user is a student
        user = Student.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid email or password.'}), 401

    return jsonify({'message': 'Login successful.'}), 200

if __name__ == '__main__':
    app.run(port=5000, debug=True)
