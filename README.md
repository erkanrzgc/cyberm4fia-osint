# CyberM4fia OSINT

Terminal tabanli bir OSINT kullanici adi tarama araci. `cyberm4fia-osint`, tek bir kullanici adini 91 platformda kontrol eder; uygun durumlarda derin profil verisi, akilli varyasyon aramasi, email/breach, web varligi, WHOIS, DNS ve subdomain bilgilerini toplar.

## Ozellikler

- 91 platformda kullanici adi kontrolu
- Kategori bazli tarama: `social`, `dev`, `gaming`, `content`, `professional`, `community`, `other`
- Derin profil taramasi ve capraz referans guven skoru
- Akilli arama: username varyasyonlari ve bagli hesap kesfi
- Email kesfi ve Gravatar kontrolu
- HIBP breach sorgusu
- Profil fotografi karsilastirma
- WHOIS, DNS ve crt.sh tabanli subdomain enumeration
- JSON ve HTML rapor export'u
- SOCKS/HTTP proxy ve Tor destegi

## Kurulum

Python `3.10+` gerekir.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Calistirma:

```bash
python3 main.py <username>
```

## Hizli Baslangic

Temel tarama:

```bash
python3 main.py testuser
```

Sadece sosyal medya platformlari:

```bash
python3 main.py testuser --category social --no-deep
```

Tam tarama ve JSON rapor:

```bash
python3 main.py testuser --full --output reports/testuser.json
```

HIBP breach kontrolu:

```bash
export HIBP_API_KEY="your_api_key"
python3 main.py testuser --breach
```

Tor uzerinden tarama:

```bash
python3 main.py testuser --tor
```

Ozel proxy ile tarama:

```bash
python3 main.py testuser --proxy socks5://127.0.0.1:9050
```

HTML rapor:

```bash
python3 main.py testuser --smart --photo --web --output reports/testuser.html
```

## CLI Secenekleri

| Flag | Alias | Aciklama |
| --- | --- | --- |
| `username` | - | Aranacak kullanici adi |
| `--smart` | `-s` | Username varyasyonlari ve kesfedilen bagli hesaplarla akilli arama |
| `--deep` | `-d` | Derin profil taramasi; varsayilan olarak acik |
| `--no-deep` | - | Derin profil taramasini kapatir |
| `--email` | `-e` | Email kesfi ve Gravatar kontrolu |
| `--web` | `-w` | Web varligi taramasi: Wayback, paste ve domain sinyalleri |
| `--full` | `-f` | `deep + smart + email + web + whois + breach + photo + dns + subdomain` |
| `--category` | `-c` | Kategori filtresi. Ornek: `social,dev,gaming` |
| `--whois` | - | 9 TLD icin WHOIS sorgusu |
| `--breach` | `--hibp` | HIBP breach kontrolu. `--email` secenegini otomatik etkinlestirir |
| `--photo` | - | Profil fotograflari arasinda perceptual hash karsilastirmasi |
| `--dns` | - | DNS kayitlarini sorgular |
| `--subdomain` | - | `crt.sh` ile subdomain enumeration yapar |
| `--tor` | `-toor` | Tarayi `socks5://127.0.0.1:9050` uzerinden calistirir |
| `--proxy` | - | HTTP/SOCKS proxy adresi |
| `--output` | `-o` | Sonuclari `.json` veya `.html` olarak kaydeder; uzanti verilmezse `.json` eklenir |
| `--timeout` | `-t` | Istek zaman asimi, saniye cinsinden |

## Optional Ozellikler ve Gereksinimler

| Ozellik | Flag | Gereken | Not |
| --- | --- | --- | --- |
| HIBP breach kontrolu | `--breach`, `--hibp` | `HIBP_API_KEY` environment variable | Anahtar yoksa uygulama uyari basar ve graceful skip yapar |
| Foto karsilastirma | `--photo` | `Pillow`, `imagehash` | Eksikse perceptual hash yerine yalnizca daha sinirli eslesme yapilabilir |
| WHOIS | `--whois` | `python-whois` | `username` icin `.com .net .org .io .dev .me .co .xyz .app` TLD'leri denenir |
| DNS / subdomain | `--dns`, `--subdomain` | `dnspython` | `crt.sh` kaynakli gecici 0 sonuc gorulebilir |
| SOCKS proxy / Tor | `--proxy`, `--tor`, `-toor` | `aiohttp-socks` | `--tor` yerel `127.0.0.1:9050` Tor servisi bekler |

## Kategori Dagilimi

- `social`: 16
- `dev`: 20
- `gaming`: 10
- `content`: 14
- `professional`: 9
- `community`: 7
- `other`: 15

Toplam: `91` platform.

## Cikti Formatlari

JSON export:

```bash
python3 main.py testuser --output result.json
```

HTML export:

```bash
python3 main.py testuser --output result.html
```

HTML raporu su bolumleri uretebilir:

- Bulunan profiller
- Derin profil detaylari
- Capraz referans skoru
- Email ve breach ozeti
- Foto eslesmeleri
- Web varligi
- WHOIS kayitlari
- DNS kayitlari
- Subdomain'ler
- Akilli arama varyasyonlari

## Ornek Senaryolar

Breach + WHOIS + DNS:

```bash
export HIBP_API_KEY="your_api_key"
python3 main.py testuser --breach --whois --dns --subdomain --output intel.json
```

Sadece gelistirici ve gaming platformlari:

```bash
python3 main.py testuser --category dev,gaming --no-deep
```

Dusuk timeout ile hizli smoke run:

```bash
python3 main.py testuser --no-deep --timeout 3
```

## Notlar

- Sonuclar hedef sitelerin anlik davranisina, rate limit'lerine ve ag durumuna gore degisebilir.
- `--breach` tek basina kullanilsa bile email kesfi otomatik acilir.
- Gecersiz veya bos kullanici adlari graceful exit ile reddedilir.
- Fake proxy veya baglanti sorunlari crash yerine bos/hatali sonuc olarak islenir.

## Gelistirme

Bagimliliklari kurduktan sonra temel smoke kontrolu:

```bash
python3 main.py --help
python3 -m compileall main.py core modules utils
```
