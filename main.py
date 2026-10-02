# main.py - WiFi Audit PRO v1.1 (Kivy -> APK)
# Auditoría defensiva de TU red + formación en hacking ético.
# Solo usar en redes con permiso del dueño.
import os
import json
import csv
import re
import socket
import shutil
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import audit

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.scrollview import ScrollView
from kivy.utils import platform as kplatform

# ---------- Tema ----------
BG = (0.043, 0.071, 0.125, 1)      # #0B1220
CARD = (0.086, 0.137, 0.231, 1)    # #16233B
ACCENT = (0.133, 0.827, 0.933, 1)  # #22D3EE
GREEN = (0.204, 0.827, 0.6, 1)
AMBER = (0.984, 0.749, 0.141, 1)
RED = (0.973, 0.443, 0.443, 1)
WHITE = (0.93, 0.95, 1.0, 1)
MUTED = (0.62, 0.70, 0.82, 1)
Window.clearcolor = BG

CYAN_H = "22D3EE"
LVL_COLOR = {"ok": "34D399", "info": "22D3EE", "aviso": "FBBF24", "peligro": "F87171"}
LVL_MARK = {"ok": "[OK]", "info": "[i]", "aviso": "[!]", "peligro": "[X]"}


class CardBtn(Button):
    def __init__(self, bg=CARD, **kw):
        kw.setdefault("background_normal", "")
        kw.setdefault("background_down", "")
        kw.setdefault("background_color", (0, 0, 0, 0))
        kw.setdefault("color", WHITE)
        super().__init__(**kw)
        self._bg = bg
        with self.canvas.before:
            Color(*self._bg)
            self._rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[14])
        self.bind(pos=self._up, size=self._up)

    def _up(self, *a):
        self._rect.pos = self.pos
        self._rect.size = self.size


def make_log():
    lab = Label(text="", markup=True, color=WHITE, size_hint_y=None,
                halign="left", valign="top")
    lab.bind(texture_size=lambda inst, val: setattr(inst, "height", val[1]))
    sc = ScrollView(size_hint=(1, 1))
    sc.add_widget(lab)
    sc.bind(width=lambda *a: setattr(lab, "text_size", (sc.width - 16, None)))
    lab.text_size = (200, None)
    return sc, lab


def set_text(lab, txt):
    Clock.schedule_once(lambda dt: setattr(lab, "text", txt))


# ---------- Red (stdlib) ----------
def ejecutar(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def storage_dir():
    try:
        app = App.get_running_app()
        if app:
            d = app.user_data_dir
            os.makedirs(d, exist_ok=True)
            return d
    except Exception:
        pass
    d = os.path.join(os.path.expanduser("~"), "wifi_historial")
    os.makedirs(d, exist_ok=True)
    return d


def ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "?"


def gateway_defecto():
    if shutil.which("ip"):
        out = ejecutar(["ip", "route", "show", "default"])
        if "via" in out:
            try:
                return out.split()[out.split().index("via") + 1]
            except Exception:
                pass
    return "?"


def ssid_android():
    if shutil.which("termux-wifi-connectioninfo"):
        try:
            d = json.loads(ejecutar(["termux-wifi-connectioninfo"]))
            if d.get("ssid"):
                return (d.get("ssid", "?"), str(d.get("rssi", "?")),
                        str(d.get("bssid", "?")))
        except Exception as e:
            print("termux api: %s" % e)
    if kplatform == "android":
        try:
            from jnius import autoclass
            act = autoclass("org.kivy.android.PythonActivity")
            ctx = act.mActivity.getApplicationContext()
            wifi = ctx.getSystemService(ctx.WIFI_SERVICE)
            info = wifi.getConnectionInfo()
            return (info.getSSID().replace('"', ""), str(info.getRssi()),
                    info.getBSSID())
        except Exception as e:
            print("pyjnius wifi: %s" % e)
    return ("?", "?", "?")


def hacer_ping(host, intentos=2):
    if not shutil.which("ping"):
        return {"host": host, "ok": False}
    try:
        r = subprocess.run(["ping", "-c", str(intentos), "-W", "1", host],
                           capture_output=True, text=True, timeout=12)
        out = (r.stdout or "") + (r.stderr or "")
        ts = re.findall(r"time[=<]([\d\.]+)\s*ms", out)
        if ts:
            t = [float(x) for x in ts]
            return {"host": host, "ok": True, "avg": sum(t) / len(t)}
        return {"host": host, "ok": r.returncode == 0}
    except Exception:
        return {"host": host, "ok": False}


def test_velocidad(mb=5):
    url = "https://speed.cloudflare.com/__down?bytes=%d" % (mb * 1024 * 1024)
    try:
        ini = time.time()
        total = 0
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            while True:
                c = resp.read(256 * 1024)
                if not c:
                    break
                total += len(c)
        seg = time.time() - ini or 0.1
        return {"ok": True, "mbps": round((total * 8 / 1_000_000) / seg, 2)}
    except Exception as e:
        return {"ok": False, "detalle": str(e)[:100]}


def base_subred(ip):
    try:
        p = ip.split(".")
        if len(p) == 4:
            return ".".join(p[:3]) + "."
    except Exception:
        pass
    return None


def ping_one(ip):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           capture_output=True, timeout=4)
        return r.returncode == 0
    except Exception:
        return False


def tabla_arp():
    macs = {}
    if shutil.which("ip"):
        out = ejecutar(["ip", "neigh", "show"])
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-f:]+)",
                             out, re.I):
            macs[m.group(1)] = m.group(2).lower()
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) >= 4 and re.match(r"\d+\.\d+\.\d+\.\d+", p[0]):
                    if re.match(r"[0-9a-f:]{17}", p[3], re.I) \
                            and "00:00:00:00:00:00" not in p[3]:
                        macs[p[0]] = p[3].lower()
    except Exception:
        pass
    return macs


def escanear_red():
    mi_ip = ip_local()
    base = base_subred(mi_ip)
    if not base:
        return {"ok": False, "detalle": mi_ip}
    vivos = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        fut = {ex.submit(ping_one, "%s%d" % (base, i)): "%s%d" % (base, i)
               for i in range(1, 255)}
        for f in as_completed(fut):
            if f.result():
                vivos.append(fut[f])
    macs = tabla_arp()
    gw = gateway_defecto()
    devs = []
    for ip in sorted(vivos, key=lambda x: int(x.split(".")[-1])):
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = "?"
        mac = macs.get(ip, "?")
        rol, vend = audit.clasificar(ip, mac, host, mi_ip, gw)
        devs.append({"ip": ip, "mac": mac, "hostname": host,
                     "rol": rol, "vendor": vend})
    return {"ok": True, "mi_ip": mi_ip, "gateway": gw,
            "total": len(devs), "dispositivos": devs}


def guardar(reg):
    d = storage_dir()
    jp = os.path.join(d, "historial.json")
    cp = os.path.join(d, "historial.csv")
    reg["fecha"] = datetime.now().isoformat(timespec="seconds")
    data = []
    if os.path.exists(jp):
        try:
            with open(jp, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                data = []
        except Exception:
            data = []
    data.append(reg)
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    nuevo = not os.path.exists(cp)
    with open(cp, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if nuevo:
            w.writerow(["fecha", "ssid", "mi_ip", "gateway", "ping_gw",
                        "ping_net", "vel_mbps", "dispositivos", "seg_score"])
        w.writerow([reg.get("fecha"), reg.get("ssid"), reg.get("mi_ip"),
                    reg.get("gateway"), reg.get("ping_gw"),
                    reg.get("ping_net"), reg.get("vel_mbps"),
                    reg.get("num_dispositivos", ""),
                    reg.get("seg_score", "")])
    try:
        if kplatform == "android":
            for dest in ("/sdcard/Download",
                         "/storage/emulated/0/Download"):
                if os.path.isdir(dest):
                    with open(os.path.join(dest, "wifi_historial.json"),
                              "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                    break
    except Exception:
        pass
    return jp


# ---------- Pantallas ----------
class HomeScreen(Screen):
    def __init__(self, app, **kw):
        super().__init__(name="home", **kw)
        self.app = app
        lay = BoxLayout(orientation="vertical", spacing=8, padding=8)
        lay.add_widget(Label(
            text="[color=%s][b]Auditor de red WiFi[/b][/color]\n[color=9DB2CE][size=13]Analiza - Escanea - Audita - Aprende[/size][/color]" % CYAN_H,
            markup=True, size_hint_y=None, height=64))
        btn = CardBtn(text="ANALIZAR MI RED", size_hint_y=None, height=58,
                      bg=(0.06, 0.42, 0.55, 1), bold=True)
        btn.bind(on_press=lambda *_: self.run())
        lay.add_widget(btn)
        fila = BoxLayout(size_hint_y=None, height=48, spacing=8)
        b_test = CardBtn(text="Probar app")
        b_test.bind(on_press=lambda *_: self.selftest())
        fila.add_widget(b_test)
        lay.add_widget(fila)
        self.sc, self.out = make_log()
        lay.add_widget(self.sc)
        self.out.text = (
            "Pulsa ANALIZAR.\nConectate a la WiFi y repite para otra red.\n\n"
            "[color=9DB2CE]Si el SSID sale '?': concede permiso de "
            "UBICACION a la app (Android 10+ lo exige para ver el nombre "
            "de la red) y activa el GPS.[/color]")
        self.add_widget(lay)

    def run(self):
        self.out.text = "Analizando..."
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            ssid, rssi, bssid = ssid_android()
            mi_ip = ip_local()
            gw = gateway_defecto()
            t = "[b]Red:[/b] %s\nBSSID: %s | Senal: %s dBm\nMi IP: %s | Gateway: %s\n\nPing...\n" % (
                ssid, bssid, rssi, mi_ip, gw)
            set_text(self.out, t)
            pg = hacer_ping(gw) if gw != "?" else {"ok": False}
            pi = hacer_ping("8.8.8.8")
            t += "Ping router: %s ms\nPing internet: %s ms\n\nVelocidad...\n" % (
                round(pg.get("avg", -1), 1) if pg.get("ok") else "FALLO",
                round(pi.get("avg", -1), 1) if pi.get("ok") else "FALLO")
            set_text(self.out, t)
            v = test_velocidad()
            t += "Velocidad: %s Mbps\n" % (v.get("mbps", "FALLO") if v.get("ok") else "fallo")
            reg = {"ssid": ssid, "bssid": bssid, "rssi": rssi,
                   "mi_ip": mi_ip, "gateway": gw,
                   "ping_gw": round(pg.get("avg", -1), 1) if pg.get("ok") else -1,
                   "ping_net": round(pi.get("avg", -1), 1) if pi.get("ok") else -1,
                   "vel_mbps": v.get("mbps", -1) if v.get("ok") else -1,
                   "num_dispositivos": "", "seg_score": ""}
            jp = guardar(reg)
            self.app.ultimo = {"ssid": ssid, "rssi": rssi, "mi_ip": mi_ip,
                               "gateway": gw}
            t += "\nGuardado en:\n%s\n\nVe a AUDITAR para la puntuacion." % jp
            set_text(self.out, t)
        except Exception as e:
            set_text(self.out, "Error: %s" % e)

    def selftest(self):
        self.out.text = "Autoprueba..."
        threading.Thread(target=self._selftest, daemon=True).start()

    def _selftest(self):
        try:
            t = "[b]Autoprueba de la app:[/b]\n"
            for nombre, ok, det in audit.auto_test():
                marca = "[color=34D399]OK[/color]" if ok else "[color=F87171]FALLO[/color]"
                t += "%s %s: %s\n" % (marca, nombre, det)
            t += "\n[color=9DB2CE]Si todo sale OK, la app funciona. Si el SSID sale '?', es solo permiso de ubicacion.[/color]"
            set_text(self.out, t)
        except Exception as e:
            set_text(self.out, "Error: %s" % e)


class ScanScreen(Screen):
    def __init__(self, app, **kw):
        super().__init__(name="scan", **kw)
        self.app = app
        lay = BoxLayout(orientation="vertical", spacing=8, padding=8)
        lay.add_widget(Label(
            text="[color=%s][b]Dispositivos en tu red[/b][/color]\n[color=9DB2CE][size=13]Solo redes con permiso - tarda 15-40 s[/size][/color]" % CYAN_H,
            markup=True, size_hint_y=None, height=56))
        btn = CardBtn(text="ESCANEAR RED", size_hint_y=None, height=58,
                      bg=(0.06, 0.42, 0.55, 1), bold=True)
        btn.bind(on_press=lambda *_: self.run())
        lay.add_widget(btn)
        self.sc, self.out = make_log()
        lay.add_widget(self.sc)
        self.out.text = "Lista quien esta conectado a tu misma red, con marca y tipo estimado."
        self.add_widget(lay)

    def run(self):
        self.out.text = "Escaneando (15-40 s)..."
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            r = escanear_red()
            if not r.get("ok"):
                set_text(self.out, "No se pudo determinar la subred.")
                return
            t = "[b]%d dispositivos[/b] (mi IP %s)\n\n" % (r["total"], r["mi_ip"])
            for x in r["dispositivos"]:
                t += "[color=%s]%s[/color]  %s\n  %s | %s\n" % (
                    CYAN_H, x["ip"], x["mac"], x["rol"],
                    (x["vendor"] if x["vendor"] != "?" else x["hostname"][:24]))
            guardar({"ssid": "escaneo", "mi_ip": r["mi_ip"],
                     "gateway": r["gateway"], "ping_gw": -1, "ping_net": -1,
                     "vel_mbps": -1, "num_dispositivos": r["total"],
                     "seg_score": "",
                     "dispositivos": r["dispositivos"]})
            t += "\nGuardado en historial."
            set_text(self.out, t)
        except Exception as e:
            set_text(self.out, "Error escaneo: %s" % e)


class AuditScreen(Screen):
    def __init__(self, app, **kw):
        super().__init__(name="audit", **kw)
        self.app = app
        lay = BoxLayout(orientation="vertical", spacing=8, padding=8)
        lay.add_widget(Label(
            text="[color=%s][b]Auditoria de seguridad[/b][/color]\n[color=9DB2CE][size=13]Puntuacion 0-100 + riesgos + como corregir[/size][/color]" % CYAN_H,
            markup=True, size_hint_y=None, height=56))
        btn = CardBtn(text="AUDITAR MI RED", size_hint_y=None, height=58,
                      bg=(0.35, 0.22, 0.05, 1), bold=True)
        btn.bind(on_press=lambda *_: self.run())
        lay.add_widget(btn)
        self.sc, self.out = make_log()
        lay.add_widget(self.sc)
        self.out.text = "Revisa cifrado, nombre de red, puertos del router y DNS. 100 = bien."
        self.add_widget(lay)

    def run(self):
        self.out.text = "Auditando..."
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            u = getattr(self.app, "ultimo", None) or {}
            ssid = u.get("ssid") or ssid_android()[0]
            rssi = u.get("rssi") or ssid_android()[1]
            mi_ip = u.get("mi_ip") or ip_local()
            gw = u.get("gateway") or gateway_defecto()
            set_text(self.out, "Revisando puertos del router...")
            puertos = audit.chequear_puertos(gw)
            try:
                with open("/etc/resolv.conf", encoding="utf-8") as f:
                    dns = [l.split()[1] for l in f if l.startswith("nameserver")]
            except Exception:
                dns = []
            score, hall, cons = audit.auditar(ssid=ssid, rssi=rssi, dns=dns,
                                             puertos=puertos, gateway=gw)
            color = "34D399" if score >= 80 else ("FBBF24" if score >= 50 else "F87171")
            t = "[size=28][color=%s][b]%d/100[/b][/color][/size]\n\n" % (color, score)
            for nivel, txt in hall:
                t += "[color=%s]%s[/color] %s\n" % (LVL_COLOR[nivel], LVL_MARK[nivel], txt)
            t += "\n[b]Como mejorar:[/b]\n"
            for c in cons:
                t += "- %s\n" % c
            guardar({"ssid": ssid, "mi_ip": mi_ip, "gateway": gw,
                     "ping_gw": -1, "ping_net": -1, "vel_mbps": -1,
                     "num_dispositivos": "", "seg_score": score})
            t += "\nPuntuacion guardada."
            set_text(self.out, t)
        except Exception as e:
            set_text(self.out, "Error auditoria: %s" % e)


class LearnScreen(Screen):
    def __init__(self, **kw):
        super().__init__(name="learn", **kw)
        lay = BoxLayout(orientation="vertical", spacing=8, padding=8)
        lay.add_widget(Label(
            text="[color=%s][b]Hacking etico[/b][/color]\n[color=9DB2CE][size=13]Aprende a defender - solo con permiso[/size][/color]" % CYAN_H,
            markup=True, size_hint_y=None, height=56))
        sc, out = make_log()
        lay.add_widget(sc)
        t = ""
        for lec in audit.LECCIONES:
            t += "[color=%s][b]%s[/b][/color]\n%s\n\n" % (CYAN_H, lec["t"], lec["x"])
        out.text = t
        self.add_widget(lay)


class HistScreen(Screen):
    def __init__(self, **kw):
        super().__init__(name="hist", **kw)
        lay = BoxLayout(orientation="vertical", spacing=8, padding=8)
        lay.add_widget(Label(text="[color=%s][b]Historial[/b][/color]" % CYAN_H,
                             markup=True, size_hint_y=None, height=40))
        btn = CardBtn(text="ACTUALIZAR", size_hint_y=None, height=50)
        btn.bind(on_press=lambda *_: self.show())
        lay.add_widget(btn)
        self.sc, self.out = make_log()
        lay.add_widget(self.sc)
        self.add_widget(lay)

    def on_enter(self):
        self.show()

    def show(self):
        try:
            d = storage_dir()
            jp = os.path.join(d, "historial.json")
            if not os.path.exists(jp):
                self.out.text = "Sin historial aun."
                return
            with open(jp, encoding="utf-8") as f:
                data = json.load(f)
            t = "[b]%d registros[/b]\n%s\n\n" % (len(data), d)
            for r in data[-15:]:
                seg = r.get("seg_score", "")
                seg = ("/%s" % seg) if seg != "" else ""
                t += "%s | %s | %s | %sMbps%s\n" % (
                    r.get("fecha"), r.get("ssid"), r.get("mi_ip"),
                    r.get("vel_mbps"), seg)
            self.out.text = t
        except Exception as e:
            self.out.text = "Error: %s" % e


class WiFiApp(App):
    def build(self):
        self.ultimo = None
        if kplatform == "android":
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([Permission.ACCESS_FINE_LOCATION,
                                     Permission.ACCESS_WIFI_STATE,
                                     Permission.ACCESS_NETWORK_STATE,
                                     Permission.INTERNET])
            except Exception:
                pass
        root = BoxLayout(orientation="vertical", spacing=4, padding=8)
        head = BoxLayout(size_hint_y=None, height=52, spacing=8)
        try:
            head.add_widget(Image(source="icon.png", size_hint_x=None, width=44))
        except Exception:
            pass
        head.add_widget(Label(text="[color=22D3EE][b]WiFi Audit PRO[/b][/color]  [color=9DB2CE][size=12]ciberseguridad defensiva[/size][/color]",
                              markup=True, halign="left", valign="middle"))
        root.add_widget(head)
        self.sm = ScreenManager()
        self.sm.add_widget(HomeScreen(self))
        self.sm.add_widget(ScanScreen(self))
        self.sm.add_widget(AuditScreen(self))
        self.sm.add_widget(LearnScreen())
        self.sm.add_widget(HistScreen())
        root.add_widget(self.sm)
        nav = BoxLayout(size_hint_y=None, height=56, spacing=6)
        for nombre, clave in (("Inicio", "home"), ("Escaner", "scan"),
                              ("Auditar", "audit"), ("Aprende", "learn"),
                              ("Historial", "hist")):
            b = CardBtn(text=nombre, font_size=13)
            b.bind(on_press=lambda inst, c=clave: setattr(self.sm, "current", c))
            nav.add_widget(b)
        root.add_widget(nav)
        return root


if __name__ == "__main__":
    WiFiApp().run()
