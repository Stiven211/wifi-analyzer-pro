[app]
title = WiFi Analyzer PRO
package.name = wifianalyzerpro
package.domain = org.ejemplo.wifi
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy,pyjnius,plyer
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 33
android.minapi = 24
android.ndk = 25b
android.gradle_dependencies =
android.enable_androidx = True
p4a.branch = v2024.01.21

[buildozer]
log_level = 2
warn_on_root = 1

[buildozer:android]
# para APK debug rápido
