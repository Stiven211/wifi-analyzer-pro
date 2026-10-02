# audit.py - Lógica de auditoría defensiva (sin dependencias, sin kivy).
# Todo es pasivo o contra TU propio router. Úsalo solo en redes con permiso.
import re
import socket

# OUI comunes (primeros 3 octetos de la MAC) -> fabricante
OUI = {
    "3C:22:FB": "Apple", "F0:18:98": "Apple", "A4:B8:05": "Apple",
    "8C:85:90": "Apple", "7C:6D:F8": "Apple", "D0:A6:37": "Apple",
    "60:F4:45": "Samsung", "84:25:DB": "Samsung", "BC:79:AD": "Samsung",
    "E8:50:8B": "Samsung", "78:59:D7": "Samsung",
    "64:CC:2E": "Xiaomi", "7C:2F:80": "Xiaomi", "50:8A:06": "Xiaomi",
    "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi",
    "AC:C1:EE": "Huawei", "E4:A7:C5": "Huawei", "00:9A:CD": "Huawei",
    "70:8B:CD": "Huawei",
    "30:05:5C": "Motorola", "44:D9:E7": "Ubiquiti", "78:45:58": "Ubiquiti",
    "B4:FB:E4": "TP-Link", "50:C7:BF": "TP-Link", "14:EB:B6": "TP-Link",
    "C0:4A:00": "TP-Link", "A0:F3:C1": "TP-Link",
    "00:1A:11": "Google", "F4:F5:D8": "Google", "54:60:09": "Google",
    "18:B4:30": "Ring/Amazon", "FC:A1:83": "Amazon", "0C:47:C9": "Amazon",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "00:0D:B9": "PC/Network", "00:50:56": "VMware", "00:0C:29": "VMware",
    "00:05:69": "VMware", "08:00:27": "VirtualBox",
    "00:1B:77": "Intel", "3C:FD:FE": "Intel",
    "FC:EC:DA": "Espressif (IoT)", "24:6F:28": "Espressif (IoT)", "30:AE:A4": "Espressif (IoT)",
    "80:7D:3A": "Espressif (IoT)", "C8:C9:A3": "Espressif (IoT)",
    "D8:A0:1D": "LG", "38:8C:50": "LG", "A8:16:D0": "LG",
    "20:C6:EB": "TCL/Roku TV", "B8:13:32": "Roku",
    "00:62:EB": "Sonos", "78:28:CA": "Sonos",
    "18:E2:C2": "HP impresora", "D8:9D:67": "HP",
    "00:1E:0B": "D-Link", "1C:AF:F7": "D-Link", "78:98:E8": "D-Link",
    "20:0C:86": "Tenda", "04:95:E6": "Tenda",
    "E0:CC:7A": "Netgear", "A0:04:60": "Netgear", "28:80:88": "Netgear",
    "F8:CA:59": "Aruba", "00:0B:86": "Aruba",
    "00:23:AB": "Cisco", "58:8D:09": "Cisco", "C8:00:84": "Cisco",
}

def vendor_de_mac(mac):
    try:
        prefijo = mac.upper().replace("-", ":")[:8]
        return OUI.get(prefijo, "?")
    except Exception:
        return "?"

def tipo_estimado(hostname, vendor, mac):
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    if any(k in h for k in ("router", "gateway", "tplink", "netgear", "huawei", "zte", "arris", "technicolor", "sagem", "livebox", "mitrastar")):
        return "Router"
    if "espressif" in v or any(k in h for k in ("esp_", "tasmota", "shelly", "sonoff", "tuya", "echo", "alexa", "chromecast", "roku", "tv")):
        return "IoT / TV / asistente"
    if "raspberry" in v:
        return "Mini-PC (Raspberry)"
    if any(k in h for k in ("iphone", "android", "galaxy", "xiaomi", "redmi", "moto", "pixel", "oneplus")):
        return "Móvil"
    if any(k in h for k in ("desktop", "laptop", "pc-", "macbook", "hp-", "lenovo", "dell")):
        return "PC / laptop"
    if any(k in h for k in ("printer", "impresora", "hp-", "canon", "epson")):
        return "Impresora"
    if vendor and vendor != "?":
        return "Dispositivo (%s)" % vendor
    return "Desconocido"

def clasificar(ip, mac, hostname, mi_ip, gateway):
    if ip == mi_ip:
        return ("Este móvil", vendor_de_mac(mac))
    if ip == gateway:
        return ("Router", vendor_de_mac(mac))
    v = vendor_de_mac(mac)
    return (tipo_estimado(hostname, v, mac), v)

PUERTOS_ROUTER = [21, 22, 23, 53, 80, 443, 8080, 8443]

def chequear_puertos(host, puertos=None, timeout=1.5):
    """TCP connect a puertos comunes de TU router. Solo informativo."""
    res = {}
    if not host or host == "?":
        return res
    for p in (puertos or PUERTOS_ROUTER):
        try:
            s = socket.create_connection((host, p), timeout=timeout)
            s.close()
            res[p] = "abierto"
        except Exception:
            res[p] = "cerrado"
    return res

DNS_PUBLICOS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}

SSID_DEFECTO = ("tplink", "netgear", "dlink", "linksys", "belkin", "arris",
                "technicolor", "sagem", "huawei", "zte", "claro", "tigo",
                "movistar", "totalplay", "izzi", "megacable", "default", "dsl-")

def auditar(ssid="", rssi="?", dns=None, puertos=None, gateway="?", cifrado=""):
    """Devuelve (score 0-100, hallazgos, consejos). Todo defensivo."""
    score = 100
    hallazgos = []  # (nivel, texto) nivel: ok/info/aviso/peligro
    consejos = []
    dns = dns or []
    puertos = puertos or {}
    c = (cifrado or "").upper()
    s = (ssid or "")

    if c in ("OPEN", "NONE", "ABIERTA", "WEP") or "OPEN" in c:
        hallazgos.append(("peligro", "Red ABIERTA o WEP: cualquiera cerca puede ver tu tráfico."))
        score -= 50
        consejos.append("Evita banca y contraseñas aquí. Usa VPN si debes conectarte.")
    elif "WPA3" in c:
        hallazgos.append(("ok", "Cifrado WPA3: lo mejor disponible hoy."))
    elif "WPA2" in c:
        hallazgos.append(("ok", "Cifrado WPA2: seguro si la clave es larga y única."))
    elif "WPA" in c:
        hallazgos.append(("aviso", "Cifrado WPA (1): obsoleto. Pide cambiar el router a WPA2/WPA3."))
        score -= 25
    else:
        hallazgos.append(("info", "Cifrado no legible desde la app: míralo en Ajustes > WiFi (busca WPA2/WPA3)."))
        score -= 5

    slow = s.lower().replace("-", "").replace("_", "").replace(" ", "")
    if any(k in slow for k in SSID_DEFECTO):
        hallazgos.append(("aviso", "Nombre de red por defecto (%s): revela la marca del router." % s))
        score -= 10
        consejos.append("Cambia el nombre WiFi y la clave de fábrica del router.")

    try:
        r = int(str(rssi))
        if r >= -60:
            hallazgos.append(("ok", "Señal %s dBm: excelente." % r))
        elif r >= -70:
            hallazgos.append(("info", "Señal %s dBm: aceptable." % r))
        else:
            hallazgos.append(("aviso", "Señal %s dBm: débil, habrá cortes." % r))
            score -= 10
            consejos.append("Acércate al router o pide un repetidor / malla.")
    except Exception:
        pass

    if puertos.get(23) == "abierto":
        hallazgos.append(("peligro", "Telnet (23) abierto en el router: protocolo inseguro de los 90s."))
        score -= 20
        consejos.append("Entra al panel del router y desactiva Telnet/SSH si no lo usas.")
    if puertos.get(80) == "abierto" or puertos.get(8080) == "abierto" or puertos.get(443) == "abierto" or puertos.get(8443) == "abierto":
        hallazgos.append(("info", "Panel web del router accesible: cambia su clave admin por defecto (hazlo a mano)."))
        consejos.append("Nunca dejes admin/admin: es lo primero que prueban los atacantes.")
    if puertos.get(22) == "abierto":
        hallazgos.append(("aviso", "SSH (22) abierto en el router: útil pero exponte solo si lo necesitas."))
        score -= 5
    if puertos.get(21) == "abierto":
        hallazgos.append(("aviso", "FTP (21) abierto: transmite claves en texto plano."))
        score -= 10

    if dns:
        pubs = [d for d in dns if d in DNS_PUBLICOS]
        if pubs:
            hallazgos.append(("ok", "DNS público (%s): difícil de envenenar." % ", ".join(pubs[:2])))
        elif gateway != "?" and gateway in dns:
            hallazgos.append(("info", "Usas el DNS del router: normal en casa, pero un router comprometido podría redirigirte."))
            consejos.append("Si dudas, cambia tu DNS a 1.1.1.1 o 9.9.9.9 en el móvil.")

    consejos.append("Activa 2FA en correo, banco y redes. Es la defensa #1.")
    return max(score, 0), hallazgos, consejos

LECCIONES = [
    {"t": "1. Qué es el hacking ético",
     "x": "Es probar la seguridad de sistemas CON permiso escrito, para corregir fallos antes que los criminales. Sin permiso no es ético: es delito. Regla de oro: permiso + alcance + no dañar + reportar."},
    {"t": "2. Reglas de oro",
     "x": "1) Solo redes y equipos tuyos o con autorización. 2) Define el alcance (qué IPs/horas). 3) No robes, borres ni rompas nada. 4) Documenta todo. 5) Reporta al dueño para que corrija."},
    {"t": "3. Tu laboratorio legal",
     "x": "Practica sin riesgo: tu propio router y tus dispositivos, máquinas virtuales (VirtualBox), y plataformas con permiso: TryHackMe, HackTheBox, PortSwigger Web Academy. Nunca pruebes técnicas contra redes ajenas."},
    {"t": "4. Lo que esta app te enseña",
     "x": "Analizar: qué red usas y su cifrado. Escanear: qué dispositivos hay (como hace un auditor al mapear). Auditar: puntuar riesgos (red abierta, Telnet, claves por defecto). Defender: DNS seguro, 2FA, actualizaciones."},
    {"t": "5. Ruta de aprendizaje",
     "x": "Redes (IP, DNS, HTTP) > Linux básico > Python > Seguridad web (OWASP Top 10) > Certificaciones (Google Cybersecurity, Security+, CEH). Con constancia, en meses entiendes el 80% de los ataques comunes."},
    {"t": "6. Defiéndete hoy",
     "x": "Claves largas únicas + gestor de claves, 2FA en todo, actualiza móvil/router, desconfía de WiFi abiertas y SMS con enlaces, revisa qué dispositivos hay en tu red cada mes con esta app."},
]

def auto_test():
    """Prueba rápida para demostrar que la app funciona (localhost + DNS + internet)."""
    out = []
    try:
        s = socket.create_connection(("127.0.0.1", 80), timeout=1)
        s.close()
        out.append(("localhost", True, "loopback responde"))
    except Exception:
        try:
            socket.gethostbyname("localhost")
            out.append(("localhost", True, "resuelve"))
        except Exception as e:
            out.append(("localhost", False, str(e)[:60]))
    try:
        ip = socket.gethostbyname("google.com")
        out.append(("DNS", True, "google.com -> " + ip))
    except Exception as e:
        out.append(("DNS", False, str(e)[:60]))
    try:
        s = socket.create_connection(("8.8.8.8", 53), timeout=3)
        s.close()
        out.append(("internet", True, "8.8.8.8:53 alcanza"))
    except Exception as e:
        out.append(("internet", False, str(e)[:60]))
    return out
