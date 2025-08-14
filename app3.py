# auditoria_acceso_windows.py
import os
import re
import subprocess
from datetime import datetime
import streamlit as st

st.set_page_config(page_title="Auditoría de Acceso Lógico - Windows", layout="wide")
st.title("Auditoría de Control de Acceso Lógico en Windows (ISO 27001 A.9)")

st.markdown("""
Este panel recopila evidencias técnicas desde Windows para evaluar controles de acceso (usuarios locales, políticas de contraseña/bloqueo y eventos 4625).
> Nota: Algunos comandos requieren ejecutarse con permisos elevados para leer el registro de Seguridad.
""")

# ---------- Helpers ----------
def run(cmd):
    try:
        return subprocess.getoutput(cmd)
    except Exception as e:
        return f"ERROR: {e}"

def parse_net_accounts(text):
    """
    Intenta extraer parámetros de 'net accounts' en español o inglés.
    """
    data = {}
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    # Patrones bilingües comunes
    patterns = {
        "MinPasswordLength": [r"Longitud mínima.*?:\s*(\d+)", r"Minimum password length.*?:\s*(\d+)"],
        "MaxPasswordAge": [r"Duración máxima de la contraseña.*?:\s*([0-9\.]+.*)", r"Maximum password age.*?:\s*(.+)"],
        "MinPasswordAge": [r"Duración mínima de la contraseña.*?:\s*(.+)", r"Minimum password age.*?:\s*(.+)"],
        "LockoutThreshold": [r"Bloqueo.*intentos.*?:\s*(\d+)", r"Lockout threshold.*?:\s*(\d+)"],
        "LockoutDuration": [r"Duración del bloqueo.*?:\s*(.+)", r"Lockout duration.*?:\s*(.+)"],
        "ResetLockoutCount": [r"Restablecer contador.*?:\s*(.+)", r"Reset lockout count.*?:\s*(.+)"],
        "PasswordHistory": [r"Recuento del historial.*?:\s*(\d+)", r"Password history length.*?:\s*(\d+)"]
    }
    for key, pats in patterns.items():
        for pat in pats:
            for line in lines:
                m = re.search(pat, line, re.IGNORECASE)
                if m:
                    data[key] = m.group(1).strip()
                    break
            if key in data:
                break
    return data

def extract_accounts_with_nonexpiring(text):
    # WMIC output contains names under "Name" column; we collect lines that look like usernames (no spaces)
    users = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("name") or line.startswith("----"):
            continue
        users.append(line)
    return users

def get_security_events_4625(limit=50):
    # Wevtutil query textual; limit via /c:N
    cmd = f'wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:{limit} /f:text'
    return run(cmd)

def get_local_users():
    return run("net user")

def get_users_password_never_expires():
    # On some systems, this attribute might be False or TRUE/False
    # Pull accounts where PasswordExpires=False
    # If WMIC is deprecated, fallback to 'net user <user>' parsing could be added.
    return run('wmic useraccount where "PasswordExpires=False" get Name')

def generate_findings(policy, nonexpiring_users, events4625_text):
    findings = []
    recs = []

    # Policy checks
    # Min length
    min_len = policy.get("MinPasswordLength")
    if min_len and min_len.isdigit() and int(min_len) < 12:
        findings.append(f"Longitud mínima de contraseña configurada en {min_len} (recomendado ≥ 12).")
        recs.append("Aumentar la longitud mínima de contraseña a 12 o superior mediante GPO.")

    # Lockout threshold
    th = policy.get("LockoutThreshold")
    if th and th.isdigit() and int(th) == 0:
        findings.append("Umbral de bloqueo de cuenta (LockoutThreshold) = 0 (sin bloqueo tras intentos fallidos).")
        recs.append("Establecer umbral de bloqueo (p. ej., 5 intentos) y duración de bloqueo (p. ej., 15-30 min).")

    # Password history
    ph = policy.get("PasswordHistory")
    if ph and ph.isdigit() and int(ph) < 12:
        findings.append(f"Historial de contraseñas configurado en {ph} (recomendado ≥ 12).")
        recs.append("Aumentar 'Password history' a al menos 12 para evitar reutilización frecuente.")

    # Non-expiring passwords
    nonexp = extract_accounts_with_nonexpiring(nonexpiring_users)
    if nonexp:
        findings.append(f"Cuentas con 'Password never expires': {', '.join(nonexp)}.")
        recs.append("Deshabilitar 'Password never expires' salvo cuentas de servicio controladas; rotación administrada.")

    # 4625 presence
    if "Event[0]" in events4625_text or "Event[" in events4625_text or "Error de inicio de sesión" in events4625_text or "An account failed to log on" in events4625_text:
        findings.append("Se observan eventos 4625 (intentos fallidos de inicio de sesión).")
        recs.append("Implementar alertas/umbrales por múltiples 4625 desde la misma IP/host; investigar orígenes.")

    # MFA (no técnica local)
    findings.append("No se pudo verificar MFA de forma local (depende de Entra ID/M365/VPN).")
    recs.append("Hacer MFA obligatorio vía Entra ID (Azure AD) / Conditional Access para accesos a sistemas críticos.")

    return findings, recs

# ---------- Panel ----------
col1, col2 = st.columns(2)

with col1:
    st.subheader("Usuarios locales")
    users_raw = get_local_users()
    st.code(users_raw, language="text")

with col2:
    st.subheader("Cuentas con contraseña que NO expira")
    nonexp_raw = get_users_password_never_expires()
    st.code(nonexp_raw, language="text")

st.subheader("Política de contraseñas/bloqueo (net accounts)")
policy_raw = run("net accounts")
st.code(policy_raw, language="text")
policy = parse_net_accounts(policy_raw)

# Mostrar policy parseada
if policy:
    st.markdown("**Parámetros clave detectados:**")
    st.json(policy)

st.subheader("Eventos de Seguridad 4625 (intentos fallidos)")
limit = st.slider("Cantidad de eventos a leer", min_value=10, max_value=200, value=50, step=10)
events4625 = get_security_events_4625(limit=limit)
st.code(events4625[:8000], language="text")  # truncar visualización

st.divider()
st.subheader("Hallazgos automáticos y recomendaciones")

findings, recs = generate_findings(policy, nonexp_raw, events4625)
if findings:
    st.markdown("### Hallazgos")
    for f in findings:
        st.write(f"- {f}")
else:
    st.write("- Sin hallazgos críticos a partir de la evidencia recopilada.")

if recs:
    st.markdown("### Recomendaciones")
    for r in recs:
        st.write(f"- {r}")

# Exportar reporte
st.divider()
st.subheader("Exportar reporte")
default_name = f"reporte_auditoria_acceso_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
fname = st.text_input("Nombre de archivo (Markdown)", value=default_name)
if st.button("Generar reporte .md"):
    lines = []
    lines.append(f"# Reporte de Auditoría de Acceso Lógico - Windows\n")
    lines.append(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append("## Evidencias\n")
    lines.append("### Usuarios locales (net user)\n")
    lines.append("```\n" + users_raw + "\n```\n")
    lines.append("### Cuentas con 'Password never expires' (WMIC)\n")
    lines.append("```\n" + nonexp_raw + "\n```\n")
    lines.append("### Política de contraseñas/bloqueo (net accounts)\n")
    lines.append("```\n" + policy_raw + "\n```\n")
    lines.append("### Eventos 4625 (wevtutil)\n")
    lines.append("```\n" + events4625[:20000] + "\n```\n")  # trunc para archivos muy grandes
    lines.append("## Hallazgos\n")
    if findings:
        for f in findings:
            lines.append(f"- {f}")
    else:
        lines.append("- Sin hallazgos críticos.")
    lines.append("\n## Recomendaciones (OCCER derivadas)\n")
    for r in recs:
        lines.append(f"- {r}")
    content = "\n".join(lines)

    with open(fname, "w", encoding="utf-8") as f:
        f.write(content)
    st.success(f"Reporte generado: {os.path.abspath(fname)}")
    st.code(content[:6000], language="markdown")

st.info("""
**Notas importantes**
- Si `wevtutil` devuelve vacío, ejecuta Streamlit como **Administrador** o habilita el registro de Seguridad.
- En algunos Windows recientes, `wmic` puede estar en desuso; si falla, revisa cuentas manualmente con `net user <usuario>` y valida "La contraseña nunca expira".
- La verificación de **MFA** no es local: documenta políticas y capturas de **Entra ID / Azure AD** (Acceso Condicional).
""")
