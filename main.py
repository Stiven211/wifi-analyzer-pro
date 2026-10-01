# main.py - WiFi Analyzer PRO (Kivy -> APK)
# Funciona en PC y en Android compilado con Buildozer.
# Solo analizar redes con permiso.
import os, json, csv, re, socket, subprocess, shutil, time, threading, platform
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.clock import Clock
from kivy.utils import platform as kplatform

def log(msg):
    print(msg, flush=True)

def ejecutar(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""

def storage_dir():
    try:
        from kivy.app import App as _App
        app = _App.get_running_app()
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
        ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        try: return socket.gethostbyname(socket.gethostname())
        except Exception: return "?"

def gateway_defecto():
    if shutil.which("ip"):
        out = ejecutar(["ip", "route", "show", "default"])
        if "via" in out:
            try: return out.split()[out.split().index("via")+1]
            except Exception: pass
    return "?"

def ssid_android():
    # 1) Termux (si se corre ahí)
    if shutil.which("termux-wifi-connectioninfo"):
        try:
            d = json.loads(ejecutar(["termux-wifi-connectioninfo"]))
            if d.get("ssid"): return d.get("ssid"), str(d.get("rssi","?")), str(d.get("bssid","?"))
        except Exception: pass
    # 2) Android vía pyjnius (cuando es APK)
    if kplatform == "android":
        try:
            from jnius import autoclass
            Activity = autoclass("org.kivy.android.PythonActivity")
            ctx = Activity.mActivity.getApplicationContext()
            wifi = ctx.getSystemService(ctx.WIFI_SERVICE)
            info = wifi.getConnectionInfo()
            ssid = info.getSSID().replace('"','')
            rssi = str(info.getRssi())
            bssid = info.getBSSID()
            return ssid, rssi, bssid
        except Exception as e:
            log(f"SSID pyjnius fallo: {e}")
    return "?", "?", "?"

def hacer_ping(host, intentos=2):
    if not shutil.which("ping"):
        return {"host":host,"ok":False}
    cmd = ["ping","-c",str(intentos),"-W","1",host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        out = (r.stdout or "") + (r.stderr or "")
        tiempos = re.findall(r"time[=<]([\d\.]+)\s*ms", out)
        if tiempos:
            t=[float(x) for x in tiempos]
            return {"host":host,"ok":True,"avg":sum(t)/len(t)}
        return {"host":host,"ok":r.returncode==0}
    except Exception:
        return {"host":host,"ok":False}

def test_velocidad(mb=5):
    url=f"https://speed.cloudflare.com/__down?bytes={mb*1024*1024}"
    try:
        ini=time.time(); total=0
        req=urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            while True:
                c=resp.read(256*1024)
                if not c: break
                total+=len(c)
        seg=time.time()-ini or 0.1
        return {"ok":True,"mbps":round((total*8/1_000_000)/seg,2)}
    except Exception as e:
        return {"ok":False,"detalle":str(e)[:120]}

def base_subred(ip):
    try:
        p=ip.split(".")
        if len(p)==4: return ".".join(p[:3])+"."
    except Exception: pass
    return None

def ping_one(ip):
    try:
        r=subprocess.run(["ping","-c","1","-W","1",ip],capture_output=True,timeout=4)
        return r.returncode==0
    except Exception:
        return False

def tabla_arp():
    macs={}
    if shutil.which("ip"):
        out=ejecutar(["ip","neigh","show"])
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-f:]+)", out, re.I):
            macs[m.group(1)]=m.group(2).lower()
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                p=line.split()
                if len(p)>=4 and re.match(r"\d+\.\d+\.\d+\.\d+",p[0]):
                    if re.match(r"[0-9a-f:]{17}",p[3],re.I) and "00:00:00:00:00:00" not in p[3]:
                        macs[p[0]]=p[3].lower()
    except Exception: pass
    return macs

def escanear_red(progreso_cb=None):
    mi_ip=ip_local()
    base=base_subred(mi_ip)
    if not base:
        return {"ok":False,"detalle":mi_ip}
    vivos=[]
    with ThreadPoolExecutor(max_workers=50) as ex:
        fut={ex.submit(ping_one,f"{base}{i}"):f"{base}{i}" for i in range(1,255)}
        n=0
        for f in as_completed(fut):
            n+=1
            if progreso_cb and n%30==0: progreso_cb(n)
            if f.result(): vivos.append(fut[f])
    macs=tabla_arp(); gw=gateway_defecto()
    devs=[]
    for ip in sorted(vivos, key=lambda x:int(x.split(".")[-1])):
        rol="tu móvil" if ip==mi_ip else ("router" if ip==gw else "dispositivo")
        try: host=socket.gethostbyaddr(ip)[0]
        except Exception: host="?"
        devs.append({"ip":ip,"mac":macs.get(ip,"?"),"hostname":host,"rol":rol})
    return {"ok":True,"mi_ip":mi_ip,"gateway":gw,"total":len(devs),"dispositivos":devs}

def guardar(registro):
    d=storage_dir()
    jp=os.path.join(d,"historial.json"); cp=os.path.join(d,"historial.csv")
    registro["fecha"]=datetime.now().isoformat(timespec="seconds")
    data=[]
    if os.path.exists(jp):
        try:
            with open(jp,encoding="utf-8") as f: data=json.load(f)
            if not isinstance(data,list): data=[]
        except Exception: data=[]
    data.append(registro)
    with open(jp,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2)
    nuevo=not os.path.exists(cp)
    with open(cp,"a",newline="",encoding="utf-8") as f:
        w=csv.writer(f)
        if nuevo: w.writerow(["fecha","ssid","mi_ip","gateway","ping_gw","ping_net","vel_mbps","dispositivos"])
        w.writerow([registro.get("fecha"),registro.get("ssid"),registro.get("mi_ip"),
            registro.get("gateway"),registro.get("ping_gw"),registro.get("ping_net"),
            registro.get("vel_mbps"),registro.get("num_dispositivos","")])
    # copia extra a Descargas en Android si se puede
    try:
        if kplatform=="android":
            for dest in ("/sdcard/Download","/storage/emulated/0/Download"):
                if os.path.isdir(dest):
                    with open(os.path.join(dest,"wifi_historial.json"),"w",encoding="utf-8") as f:
                        json.dump(data,f,ensure_ascii=False,indent=2)
                    break
    except Exception: pass
    return jp

class Root(BoxLayout):
    def __init__(self, **kw):
        super().__init__(orientation="vertical", padding=10, spacing=8, **kw)
        self.add_widget(Label(text="WiFi Analyzer PRO\nSolo redes con permiso", size_hint_y=None, height=60, bold=True))
        self.salida = Label(text="Pulsa Analizar.\nConéctate a la WiFi y repite para otra red.",
            size_hint_y=1, halign="left", valign="top", markup=True)
        self.salida.bind(size=self.salida.setter('text_size'))
        sc = ScrollView(size_hint=(1,1)); sc.add_widget(self.salida); self.add_widget(sc)
        fila1 = BoxLayout(size_hint_y=None, height=52, spacing=6)
        fila2 = BoxLayout(size_hint_y=None, height=52, spacing=6)
        b1=Button(text="Analizar WiFi"); b1.bind(on_press=lambda *_: self.run_analizar(False))
        b2=Button(text="Analizar + Escanear"); b2.bind(on_press=lambda *_: self.run_analizar(True))
        b3=Button(text="Solo Escanear red"); b3.bind(on_press=lambda *_: self.run_scan())
        b4=Button(text="Ver historial"); b4.bind(on_press=lambda *_: self.run_historial())
        fila1.add_widget(b1); fila1.add_widget(b2)
        fila2.add_widget(b3); fila2.add_widget(b4)
        self.add_widget(fila1); self.add_widget(fila2)
        self.add_widget(Label(text="Guarda en historial.json/csv automático", size_hint_y=None, height=24, font_size=12))

    def set_txt(self, t):
        def _u(dt): self.salida.text = t
        Clock.schedule_once(_u)

    def run_analizar(self, con_scan):
        self.set_txt("Analizando... no cierres la app")
        threading.Thread(target=self._analizar, args=(con_scan,), daemon=True).start()

    def run_scan(self):
        self.set_txt("Escaneando red (15-40s)...")
        threading.Thread(target=self._scan, daemon=True).start()

    def run_historial(self):
        try:
            d=storage_dir(); jp=os.path.join(d,"historial.json")
            if not os.path.exists(jp): self.set_txt("Sin historial aún."); return
            with open(jp,encoding="utf-8") as f: data=json.load(f)
            ult=data[-10:]
            t=f"[b]Historial ({len(data)} registros)[/b]\n"+d+"\n\n"
            for r in ult:
                t+=f"{r.get('fecha')} | {r.get('ssid')} | {r.get('mi_ip')} | {r.get('vel_mbps')}Mbps | dev:{r.get('num_dispositivos')}\n"
            self.set_txt(t)
        except Exception as e:
            self.set_txt(f"Error historial: {e}")

    def _analizar(self, con_scan):
        try:
            ssid,rssi,bssid=ssid_android()
            mi_ip=ip_local(); gw=gateway_defecto()
            t=f"[b]Red:[/b] {ssid}\nBSSID: {bssid} | RSSI: {rssi} dBm\nMi IP: {mi_ip} | Gateway: {gw}\n\nPing...\n"
            self.set_txt(t)
            pg=hacer_ping(gw) if gw!="?" else {"ok":False}
            pi=hacer_ping("8.8.8.8")
            t+=f"Ping gateway: {round(pg.get('avg',-1),1) if pg.get('ok') else 'FALLO'} ms\n"
            t+=f"Ping internet: {round(pi.get('avg',-1),1) if pi.get('ok') else 'FALLO'} ms\n\nVelocidad (5MB)...\n"
            self.set_txt(t)
            v=test_velocidad()
            t+=f"Velocidad: {v.get('mbps','FALLO')} Mbps\n" if v.get("ok") else "Velocidad: fallo\n"
            num=""; devs=[]
            if con_scan:
                t+="\nEscaneando LAN...\n"; self.set_txt(t)
                r=escanear_red()
                if r.get("ok"):
                    num=r["total"]; devs=r["dispositivos"]
                    t+=f"\n[b]{num} dispositivos:[/b]\n"
                    for x in devs[:40]:
                        t+=f"{x['ip']} {x['mac']} [{x['rol']}]\n"
                else: t+="\nEscaneo falló.\n"
            reg={"ssid":ssid,"bssid":bssid,"rssi":rssi,"mi_ip":mi_ip,"gateway":gw,
                "ping_gw":round(pg.get("avg",-1),1) if pg.get("ok") else -1,
                "ping_net":round(pi.get("avg",-1),1) if pi.get("ok") else -1,
                "vel_mbps":v.get("mbps",-1) if v.get("ok") else -1,
                "num_dispositivos":num,"dispositivos":devs}
            jp=guardar(reg)
            t+=f"\nGuardado en:\n{jp}"
            self.set_txt(t)
        except Exception as e:
            self.set_txt(f"Error: {e}")

    def _scan(self):
        try:
            def cb(n): pass
            r=escanear_red(cb)
            if not r.get("ok"):
                self.set_txt("No se pudo determinar subred."); return
            t=f"[b]{r['total']} dispositivos[/b] (mi IP {r['mi_ip']})\n\n"
            for x in r["dispositivos"]:
                t+=f"{x['ip']:15} {x['mac']:17} {x['hostname'][:25]} [{x['rol']}]\n"
            guardar({"ssid":"escaneo","mi_ip":r["mi_ip"],"gateway":r["gateway"],
                "ping_gw":-1,"ping_net":-1,"vel_mbps":-1,
                "num_dispositivos":r["total"],"dispositivos":r["dispositivos"]})
            t+="\nGuardado en historial."
            self.set_txt(t)
        except Exception as e:
            self.set_txt(f"Error escaneo: {e}")

class WiFiApp(App):
    def build(self):
        if kplatform=="android":
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([Permission.ACCESS_FINE_LOCATION, Permission.ACCESS_WIFI_STATE,
                    Permission.ACCESS_NETWORK_STATE, Permission.INTERNET,
                    Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
            except Exception: pass
        return Root()

if __name__=="__main__":
    WiFiApp().run()
