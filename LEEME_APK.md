# WiFi Analyzer PRO - Proyecto APK (Kivy + Buildozer)

App para Android que:
- Analiza la WiFi conectada (cualquiera, reconéctate y repite)
- Escanea dispositivos de tu misma red (ping sweep + ARP + hostname)
- Guarda historial automático en `historial.json` + `historial.csv`
- Solo usar en redes con permiso del dueño.

## Archivos
- `main.py` = app completa (Kivy)
- `buildozer.spec` = config para compilar
- `.github/workflows/build-apk.yml` = compila APK en la nube gratis

## Opción 1: Compilar gratis sin instalar nada (recomendado)
1. Crea un repo en GitHub y sube el contenido de `wifi_app/` (main.py, buildozer.spec, .github/)
2. Ve a pestaña Actions -> Build APK -> Run
3. Descarga el artefacto `wifi-analyzer-apk` (un .apk debug)
4. Pásalo al móvil e instala (permite "orígenes desconocidos").
5. Al abrir, concede Ubicación + WiFi (necesario para SSID en Android 10+).

## Opción 2: Google Colab (10 min)
```
!apt update && apt install -y openjdk-17-jdk unzip
!pip install buildozer cython
# sube main.py + buildozer.spec a /content, luego:
!yes | buildozer -v android debug
```
Descarga `bin/*.apk` desde archivos.

## Opción 3: PC Linux
```bash
sudo apt install openjdk-17-jdk python3-pip unzip
pip install buildozer cython
buildozer -v android debug
# sale en bin/wifianalyzerpro-1.0-debug.apk
adb install bin/*.apk
```

## Uso en la app
- **Analizar WiFi**: SSID, BSSID, RSSI, IP, gateway, ping, velocidad. Guarda.
- **Analizar + Escanear**: lo anterior + lista 192.168.x.1-254 activos con MAC/hostname. Tarda 15-40s.
- **Solo Escanear**: descubrimiento LAN.
- **Ver historial**: últimos 10, archivo completo en datos de app + copia en Download/wifi_historial.json (si hay permiso).

## Permisos (ya incluidos en buildozer.spec)
INTERNET, ACCESS_WIFI_STATE, ACCESS_NETWORK_STATE, FINE_LOCATION (para SSID).

## Probar sin compilar (PC)
```
pip install kivy
python main.py
```

## Alternativa inmediata sin APK: Termux
Si no quieres compilar aún, usa `wifi_analisis_pro.py` en Termux:
```
pkg install python -y
python wifi_analisis_pro.py
# menú: 1 rápido, 2 con escaneo, 3 solo escaneo, 4 historial
# guarda en ~/wifi_historial/
python wifi_analisis_pro.py --auto-scan
```
