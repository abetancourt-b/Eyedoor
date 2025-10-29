from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore
import re
import random
import string

app = Flask(__name__)
app.secret_key = "ABCDE-FGHIJ-LMNOP"

cred = credentials.Certificate("eyedoor-firebase.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

CLAVE_PERMITIDA = "ABCDE-FGHIJ-KLMNO"

CODE_REGEX = re.compile(r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$')

def get_user_by_email(email):
    users_ref = db.collection("users")
    query = users_ref.where("email", "==", email).get()
    if not query:
        return None
    doc = query[0]
    data = doc.to_dict()
    data["id"] = doc.id
    return data

def create_user(email, password_hash, product_code):
    db.collection("users").add({
        "email": email,
        "password_hash": password_hash,
        "product_code": product_code
    })

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = get_user_by_email(email)
        if not user:
            flash("No existe una cuenta con ese correo.", "error")
            return redirect(url_for('login'))

        if not check_password_hash(user['password_hash'], password):
            flash("Contraseña incorrecta.", "error")
            return redirect(url_for('login'))

        session['user_email'] = user['email']
        session['product_code'] = user['product_code']

        flash("Inicio de sesión exitoso. ¡Bienvenido!", "success")
        return redirect(url_for('bienvenido'))

    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        product_code = request.form.get('product_code', '').strip().upper()

        if not email:
            flash("Debes ingresar un correo electrónico.", "error")
            return redirect(url_for('registro'))

        if len(password) < 6:
            flash("La contraseña debe tener al menos 6 caracteres.", "error")
            return redirect(url_for('registro'))

        if password != password2:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for('registro'))

        if get_user_by_email(email):
            flash("Ya existe una cuenta con ese correo.", "error")
            return redirect(url_for('registro'))

        if product_code != CLAVE_PERMITIDA:
            flash("Código de producto inválido. Solo se acepta ABCDE-FGHIJ-KLMNO.", "error")
            return redirect(url_for('registro'))

        password_hash = generate_password_hash(password)
        try:
            create_user(email, password_hash, product_code)
            flash("Cuenta creada exitosamente. Ahora puedes iniciar sesión.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error al crear la cuenta: {e}", "error")
            return redirect(url_for('registro'))

    return render_template('registro.html')

@app.route('/bienvenido')
def bienvenido():
    if 'user_email' not in session:
        flash("Debes iniciar sesión primero.", "error")
        return redirect(url_for('login'))

    email = session.get('user_email')
    code = session.get('product_code')
    return render_template('bienvenido.html', email=email, product_code=code)


@app.route('/recuperar')
def recuperar():
    return render_template('recuperar.html')


@app.route('/_debug_list_users')
def debug_list_users():
    users = db.collection("users").get()
    return {
        "users": [
            {"id": u.id, "email": u.to_dict().get("email"), "product_code": u.to_dict().get("product_code")}
            for u in users
        ]
    }

if __name__ == '__main__':
    app.run(debug=True)
