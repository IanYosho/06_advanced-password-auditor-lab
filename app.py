import streamlit as st
import string
import math
import hashlib
import requests
import secrets

st.set_page_config(
    page_title="Advanced Password Auditor",
    page_icon="🔐",
    layout="centered"
)

def generate_password(length):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password, alphabet

def calculate_entropy(password, alphabet):
    pool_size = len(alphabet)
    return len(password) * math.log2(pool_size) if password else 0

def check_pwned_api(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {'User-Agent': 'Streamlit-Password-Auditor'}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            for line in response.text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    return True, int(count)
            return False, 0
        return None, 0
    except requests.RequestException:
        return None, 0

# UI Design
st.title("🔐 Advanced Password Auditor & Generator")
st.markdown("Cryptographic entropy evaluation and data breach verification via **k-Anonymity**.")

tab1, tab2 = st.tabs(["Auditor de Contraseñas", "Generador Criptográfico"])

with tab1:
    st.subheader("Auditar Contraseña Existente")
    user_pass = st.text_input("Ingresa una contraseña para analizar:", type="password")
    
    if user_pass:
        alphabet = string.ascii_letters + string.digits + string.punctuation
        entropy = calculate_entropy(user_pass, alphabet)
        is_pwned, count = check_pwned_api(user_pass)
        
        col1, col2 = st.columns(2)
        col1.metric("Longitud", f"{len(user_pass)} caracteres")
        col2.metric("Entropía Estimada", f"{entropy:.2f} bits")
        
        if is_pwned:
            st.error(f"❌ **BRECHA DETECTADA:** Esta contraseña figura en {count:,} filtraciones públicas conocidas.")
        elif is_pwned is False:
            st.success("✅ **SEGURA:** No se encontraron coincidencias en brechas públicas analizadas.")
        else:
            st.warning("⚠️ Error al consultar el servicio de validación de brechas.")

with tab2:
    st.subheader("Generar Contraseña Segura")
    pass_len = st.slider("Longitud de la clave:", min_value=8, max_value=64, value=20)
    
    if st.button("Generar Clave"):
        new_pass, alpha = generate_password(pass_len)
        entropy_gen = calculate_entropy(new_pass, alpha)
        
        st.code(new_pass, language="text")
        st.info(f"Entropía criptográfica: **{entropy_gen:.2f} bits** | Pool: {len(alpha)} caracteres")