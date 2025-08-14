# archivo: auditoria_acceso.py

import streamlit as st
import pandas as pd
import subprocess
import os

# Función para obtener usuarios locales
def get_system_users():
    try:
        result = subprocess.getoutput("net user")
        users = result.splitlines()[4:-2]  # Ajuste según salida de 'net user'
        users_list = []
        for line in users:
            users_list += line.split()
        return users_list
    except Exception as e:
        return [f"Error al obtener usuarios: {e}"]

# Función para detectar cuentas duplicadas en Excel
def check_duplicate_accounts(df):
    duplicates = df[df.duplicated(subset=['Usuario'], keep=False)]
    return duplicates

# Función para revisar intentos fallidos (simulado)
def check_failed_logins(df):
    # df debe tener columnas: Usuario, Fecha, Estado
    failed = df[df['Estado'] == 'Fallido']
    return failed

# Función para verificar MFA (simulado)
def check_mfa():
    # Aquí puedes conectarlo a Azure AD si aplica, por ahora simulado
    mfa_enabled = True
    return "Sí" if mfa_enabled else "No"

# ------------------- STREAMLIT -------------------
st.title("🛡 Auditoría de Acceso Lógico - Windows")

# Mostrar usuarios del sistema
st.subheader("Usuarios del sistema")
users = get_system_users()
st.write(users)

# Cargar Excel para validación de cuentas
st.subheader("Validación de cuentas compartidas e intentos fallidos")
uploaded_file = st.file_uploader("Cargar Excel de prueba", type=["xlsx"])
if uploaded_file:
    df = pd.read_excel(uploaded_file)

    # Validar cuentas duplicadas
    st.markdown("⚠️ **Cuentas duplicadas:**")
    duplicates = check_duplicate_accounts(df)
    if not duplicates.empty:
        st.dataframe(duplicates)
    else:
        st.write("No se encontraron cuentas duplicadas.")

    # Validar intentos fallidos
    st.markdown("🚨 **Intentos fallidos de acceso:**")
    failed = check_failed_logins(df)
    if not failed.empty:
        st.dataframe(failed)
    else:
        st.write("No se detectaron intentos fallidos.")

# Verificar MFA
st.subheader("🔐 Estado de MFA")
st.write(check_mfa())
