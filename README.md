# RS Otorisasi: Sistem Rekam Medis Rumah Sakit

Aplikasi web sederhana (REST API Express.js + satu halaman HTML) untuk ALP Keamanan Siber, Universitas Ciputra.
Menerapkan:

- **Autentikasi JWT** (username/password, bcrypt, access token 15 menit + refresh token 7 hari dengan rotation)
- **Google Login (OAuth 2.0 Authorization Code flow)** yang menghasilkan JWT aplikasi
- **RBAC** dengan 4 role: `admin`, `dokter`, `perawat`, `pasien`
- **ABAC** berdasarkan atribut user (ruang, departemen, clearance, onDuty, ID pasien) dan atribut data (pemilik, ruang, departemen, sensitivitas)
- **Gabungan RBAC + ABAC** untuk data rahasia, catatan perawatan, serta membuat/menghapus rekam medis

## Menjalankan

Butuh Node.js >= 20.12.

```bash
npm install
cp .env.example .env   # isi JWT_SECRET, dan kredensial Google jika ingin login Google
npm start              # http://localhost:3000
npm test               # uji matriks policy + alur HTTP
```

### Setup Google OAuth

1. Buka [Google Cloud Console](https://console.cloud.google.com) dan buat project.
2. **APIs & Services > OAuth consent screen**: pilih *External*, isi nama aplikasi & email, tambahkan email Anda sebagai *test user*.
3. **APIs & Services > Credentials > Create Credentials > OAuth client ID**, tipe *Web application*.
4. Authorized redirect URI: `http://localhost:3000/api/auth/google/callback`.
5. Salin Client ID & Client Secret ke `.env`, lalu restart server.

User Google yang emailnya sama dengan akun lokal akan ditautkan ke akun itu. Email baru otomatis dibuat sebagai `pasien` (hak paling rendah); admin bisa mengubah role/atributnya lewat menu Manajemen User.

## Akun demo

| Username | Password | Role | Departemen | Ruang | Clearance | onDuty | ID Pasien |
|---|---|---|---|---|---|---|---|
| admin | admin123 | admin | Manajemen | - | 3 | true | - |
| dr.andi | dokter123 | dokter | Penyakit Dalam | Melati | 3 | true | - |
| dr.sari | dokter123 | dokter | Anak | Anggrek | 2 | true | - |
| ns.budi | perawat123 | perawat | Keperawatan | Melati | 3 | true | - |
| ns.citra | perawat123 | perawat | Keperawatan | Anggrek | 1 | false | - |
| dewi | pasien123 | pasien | - | - | - | - | P001 |
| eko | pasien123 | pasien | - | - | - | - | P002 |

Rekam medis awal:

| ID | Pasien | Ruang | Departemen | Sensitivitas |
|---|---|---|---|---|
| 1 | Dewi (P001) | Melati | Penyakit Dalam | 1 Umum |
| 2 | Dewi (P001) | Melati | Penyakit Dalam | 3 Rahasia |
| 3 | Eko (P002) | Anggrek | Anak | 1 Umum |
| 4 | Eko (P002) | Anggrek | Anak | 2 Sensitif |
| 5 | Fajar (P003) | Melati | Bedah | 2 Sensitif |

## Access policy

Semua aturan ada di [`src/policy.js`](src/policy.js). Setiap penolakan mengembalikan `403` beserta ID policy dan alasannya, dan setiap keputusan dicatat di terminal (`[AUTHZ] ...`).

**RBAC (izin per role)**

| ID | Role | Izin |
|---|---|---|
| R1 | admin | `user:read`, `user:manage`, semua aksi rekam medis tanpa batasan atribut |
| R2 | dokter | `record:read`, `record:create`, `record:update`, `record:delete` |
| R3 | perawat | `record:read`, `record:update` (tambah catatan) |
| R4 | pasien | `record:read` |
| R5 | semua | Aksi di luar izin role ditolak (mis. perawat menghapus, non-admin membuka `/api/admin/*`) |

**ABAC (atribut user vs atribut data)**

| ID | Aturan |
|---|---|
| A1 | Pasien hanya dapat melihat rekam medis dengan `patientId` miliknya |
| A2 | Dokter/perawat hanya dapat mengakses rekam medis pasien di `ward` (ruang rawat) yang sama |
| A3 | `clearance` user harus >= `sensitivity` rekam medis |

**Gabungan RBAC + ABAC**

| ID | Aturan |
|---|---|
| G1 | Data `Rahasia` (sensitivitas 3) hanya untuk role **dokter** + ruang sama + clearance 3. Perawat ditolak walau clearance 3 |
| G2 | Tambah catatan: role **dokter/perawat** + ruang sama + clearance cukup + `onDuty = true` |
| G3 | Buat/hapus rekam medis: role **dokter** + ruang sama + clearance cukup + `department` sama dengan departemen rekam medis |

## Endpoint

Semua endpoint selain `/api/auth/*`, `/api` dan `/api/policies` butuh header `Authorization: Bearer <access token>`.

| Method | Path | Keterangan | Policy |
|---|---|---|---|
| POST | `/api/auth/login` | `{username, password}` -> `accessToken`, `refreshToken` | - |
| POST | `/api/auth/refresh` | `{refreshToken}` -> pasangan token baru (token lama dicabut) | - |
| POST | `/api/auth/logout` | `{refreshToken}` -> cabut refresh token | - |
| GET | `/api/auth/google` | Redirect ke halaman login Google | - |
| GET | `/api/auth/google/callback` | Tukar code -> token Google -> profil -> JWT aplikasi | - |
| GET | `/api/me` | Profil, atribut user, dan klaim token | autentikasi |
| GET | `/api/records` | Rekam medis yang boleh dibaca (difilter) | R, A1-A3, G1 |
| GET | `/api/records/:id` | Detail rekam medis | R, A1-A3, G1 |
| POST | `/api/records` | `{patientId, patientName, diagnosis, sensitivity, ward?, department?}` | R, A2, A3, G3 |
| POST | `/api/records/:id/notes` | `{text}` tambah catatan perawatan | R, A2, A3, G1, G2 |
| DELETE | `/api/records/:id` | Hapus rekam medis | R, A2, A3, G3 |
| GET | `/api/admin/users` | Daftar user | R1/R5 |
| PATCH | `/api/admin/users/:id` | Ubah `role`, `department`, `ward`, `clearance`, `onDuty`, `patientId` | R1/R5 |
| GET | `/api/policies` | Izin per role | - |

Contoh dengan curl:

```bash
TOKEN=$(curl -s -X POST localhost:3000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"dr.andi","password":"dokter123"}' | node -pe 'JSON.parse(require("fs").readFileSync(0)).accessToken')
curl -s localhost:3000/api/records -H "Authorization: Bearer $TOKEN"
curl -s -X DELETE localhost:3000/api/records/5 -H "Authorization: Bearer $TOKEN"   # 403 G3
```

## Struktur

```
src/server.js   route REST API + audit log keputusan
src/auth.js     login JWT, refresh/logout, Google OAuth 2.0, middleware authenticate
src/policy.js   RBAC + ABAC (Policy Decision Point)
src/data.js     data demo in-memory (user + rekam medis)
public/         antarmuka web (satu file HTML)
test/           uji policy dan alur HTTP (node:test)
```

Catatan: data disimpan in-memory sehingga kembali ke kondisi awal setiap server restart.
