from flask import Flask, request, jsonify, render_template, g
from cryptography.fernet import Fernet
import sqlite3

# Initialize Flask app
app = Flask(__name__)

# Generate a key and initialize the Fernet cipher
key = Fernet.generate_key()
cipher_suite = Fernet(key)

DATABASE = 'encrypted_data.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Initialize the database
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS encrypted_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_card TEXT NOT NULL,
            encrypted_cvv TEXT NOT NULL
        )''')
        db.commit()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        if not data or 'card_number' not in data or 'cvv' not in data:
            return jsonify({'error': 'Missing card_number or cvv in the request'}), 400

        card_number = data.get('card_number')
        cvv = data.get('cvv')

        if not isinstance(card_number, str) or not card_number.isdigit():
            return jsonify({'error': 'card_number must be a string of digits'}), 400
        if not isinstance(cvv, str) or not cvv.isdigit() or len(cvv) != 3:
            return jsonify({'error': 'cvv must be a 3-digit string'}), 400

        encrypted_card = cipher_suite.encrypt(card_number.encode())
        encrypted_cvv = cipher_suite.encrypt(cvv.encode())

        db = get_db()
        cursor = db.cursor()
        cursor.execute('INSERT INTO encrypted_data (encrypted_card, encrypted_cvv) VALUES (?, ?)', 
                       (encrypted_card.decode(), encrypted_cvv.decode()))
        db.commit()

        return jsonify({
            'encrypted_card': encrypted_card.decode(),
            'encrypted_cvv': encrypted_cvv.decode()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        if not data or 'encrypted_card' not in data or 'encrypted_cvv' not in data:
            return jsonify({'error': 'Missing encrypted_card or encrypted_cvv in the request'}), 400

        encrypted_card = data.get('encrypted_card')
        encrypted_cvv = data.get('encrypted_cvv')

        if not isinstance(encrypted_card, str) or not isinstance(encrypted_cvv, str):
            return jsonify({'error': 'Both encrypted_card and encrypted_cvv must be strings'}), 400

        decrypted_card = cipher_suite.decrypt(encrypted_card.encode())
        decrypted_cvv = cipher_suite.decrypt(encrypted_cvv.encode())

        return jsonify({
            'decrypted_card': decrypted_card.decode(),
            'decrypted_cvv': decrypted_cvv.decode()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/records')
def records():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT encrypted_card, encrypted_cvv FROM encrypted_data')
        records = cursor.fetchall()
        return render_template('records.html', records=records)
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
