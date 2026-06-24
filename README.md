# course-homework17

### case 1

[link](https://www.malware-traffic-analysis.net/2024/08/15/index.html)
WarmCookie

---

**victim's details**

IP: 10.8.15.133
Domain: wireshark-ws.online | DC: 10.8.15.4 (WIRESHARK-WS-DC)
User: Pierce Lucero
Time: 2024-08-15, 0:11 UTC
OC: Windows

Пользователь перешел по фишинговой ссылке в письме, перенаправившей его на компроментированный домен.С него загружено
Домен первого этапа: quote.checkfedexexp.com
Файл: Invoice 876597035_003.zip
Внутри архива: Invoice-876597035-003-8331775-8334138.js (SHA1: 2d81f6cfb49f992494b78bfe82fa142c5004a554
При запуске через wscript.exe инициализируется загрузка DLL payload со след. домена: business.checkfedexexp.com
SHA256 DLL (WarmCookie) b7aec5f73d2a6bbd8cd920edb4760e2edadc98c3a45bf4fa994d47ca9cbd02f6

**С2-коммуникация**
После установки бэкдора хост начал отправлять HTTP POST-запросы напрямую на IP-адрес
POST http://72.5.43.29/ — HTTP 200 OK
Трафик на 72.5.43.29 доминировал в сессии: 3497 пакетов.

**IOC**
ip: 72.5.43.29:80
Domain 1: quote.checkfedexexp.com
Domain 2: business.checkfedexexp.com
URL: /data/0f60a3e7baecf2748b1c8183ed37d1e4
Hash(SHA256): b7aec5f73d2a6bbd8cd920edb4760e2edadc98c3a45bf4fa994d47ca9cbd02f6
Hash(SHA1): 2d81f6cfb49f992494b78bfe82fa142c5004a554
User-Agent: Microsoft BITS/7.8
Filename: Invoice-876597035-003.zip

---

### case 2

[link](https://www.malware-traffic-analysis.net/2024/07/30/index.html)
You Dirty Rat!

---

**victim's details**

IP:172.16.1.66
MAC:00:1e:64:ec:f3:08
Hostname: DESKTOP-SKBR25F
Username:ccollier
OC: Microsoft Windows 11 Pro (64-bit)
Antivirus: Windows Defender
IP DC: 172.16.1.4 (WIRESHARK-WS-DC, MAC: 00:1e:64:ec:f3:08)
Time: 2024-07-30, 04:38 UTC
Time C2-activity: 2024-07-30, 04:40 UTC

Анализ трафика начался с аномального исходящего TCP-соединения от 172.16.1.66 к внешнему IP 141.98.10.79 на нестандартный порт 12132. В пакетах обнаружены pipe-delimited строки формата STRRAT C2-чекина:
ping|STRRAT|1BE8292C|DESKTOP-SKBR25F|ccollier|Microsoft Windows 11 Pro|64-bit|Windows Defender||1.6|US:United States|Not Installed|1 Sec136

```
Инструмент Zui (Brim) с Suricata-алертами однозначно классифицировал трафик:
ET MALWARE STRRAT CnC Checking [Severity: Critical]
TShark-фильтр для обнаружения:
tshark -r pcap.pcap -Y 'frame contains "ping|STRRAT|"' -T fields -e ip.src -e ip.dst
```

**IOC**

IP(C2): 141.98.10.79
PORT: 12132
User: ccollier @ DESKTOP-SKBR25F

---

### case 3

[link](https://www.malware-traffic-analysis.net/2024/11/26/index.html)
Nemotodes

---

**victim's details**
IP: 10.11.26.183
Hostname: DESKTOP-B8TKQ49 (domain: NEMOTODES.HEALTH)
Username: oboomwald
Time: 2024-11-26, 04:49 UTS
C2-server: 194.180.191.64 (fandoorcrackededpak.com)

NetSupport RAT распространяется через drive-by загрузку с компрометированных сайтов или через fake browser update. Жертва посетила заражённый ресурс, после чего был автоматически загружен и запущен клиент NetSupport Manager.

**C2-communications**
POST http://194.180.191.64/fakeurl.htm HTTP/1.1
User-Agent: NetSupport Manager/1.3
Content-Type: application/x-www-form-urlencoded
Body: CMD=POLL (polling / heartbeat)
Body: CMD=ENCD DATA=<base64-like obfuscated payload>

DNS-traffic
wpad.nemotoads.health — WPAD-запрос
\*.trafficmanager.net — Microsoft CDN

**IOC**

IP(C2): 194.180.191.64
Domain(C2):fandoorcrackededpak.com
URL: /fakeurl.htm
User-Agent: NetSupport Manager/1.3
Domain: wpad.nemotoads.health
User: oboomwald @ NEMOTODES.HEALTH
Hash: $krb5pa$18$oboomwald$NEMOTODES...

---
