# cyberm4fia-osint — Yapilacaklar

## Sprint 9: Canli Ilerleme + Interaktif Graph  ✅
- [x] WebSocket / SSE ile scan progress (her phase bitince web UI'a event)
- [x] D3.js veya Cytoscape ile interaktif entity graph (web UI'da tiklanabilir ag haritasi)
- [x] Graph uzerinde node detayi (profil, email, telefon, cuzdana tikla -> detay paneli)

## Sprint 10: Zamanlanmis Tarama + Bildirim  ✅
- [x] Scheduled scan — watchlist'teki kullanicilari cron/timer ile otomatik tara
- [x] Degisiklik algila (yeni platform, kaybolan profil) ve bildir
- [x] Telegram bildirim hook'u (scan bitti, yeni bulgu)
- [x] Webhook desteği (genel entegrasyon icin POST callback)

## Sprint 11: Docker + Playwright Genisleme  ✅
- [x] Dockerfile — Tor + Playwright + tum bagimliliklar tek image
- [x] docker-compose.yml (API + Tor + isteğe bağlı CLI profili)
- [x] Playwright'i JS-heavy platformlarda (Instagram, X, TikTok, Threads, LinkedIn) varsayilan yap
- [x] Playwright screenshot'lari scan sonucuna ekle (--screenshots)

## Sprint 12: Geolocation Heatmap  ✅
- [x] core/geo.py — SQLite-cached Nominatim geocoder + GeoPoint dataclass
- [x] --geocode CLI flag + _phase_geocode engine phase
- [x] GET /heatmap/{username} API (duplicate coord folding)
- [x] Leaflet + Leaflet.heat web panel, OSM tiles, markers with popups

## Sprint 13: Username Correlation Scoring  ✅
- [x] core/correlation.py — evidence-first scorer, probabilistic OR
  (email/phone/crypto/name/location/bio/alias/avatar signals)
- [x] GET /correlate?a=&b= API endpoint
- [x] --correlate user_a,user_b CLI flag
- [x] Web UI panel with verdict badge + signals table

## Backlog (oncelik sirasiyla)
- [ ] Report comparison UI — iki scan'i yan yana diff goruntule
- [ ] Social graph — follow/follower overlap (GitHub, Twitter API)
- [ ] OSINT investigation/case yonetimi — bookmark, etiket, not sistemi
- [ ] Multi-user auth (JWT) — REST API icin
- [ ] Export: CSV, Excel formatlari
- [ ] Proxy pool rotasyonu — birden fazla proxy round-robin
- [ ] Mobile-responsive web UI
