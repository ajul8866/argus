# Audit kemudahan penggunaan Argus

Audit ini meninjau hambatan untuk pengguna yang ingin memilih repositori,
menjalankan audit, membaca temuan, dan mengunduh laporan. Ini adalah audit
alur produk dan aturan penggunaan, bukan klaim bahwa seluruh source code
bebas kerentanan.

## Alur utama setelah perbaikan

1. Pilih folder repositori melalui **Browse folders**. Nama proyek terisi otomatis.
2. Tekan **Create project**. Argus langsung mengimpor berkas.
3. Tekan **New audit**, lalu **Start audit**. Nilai bawaan berasal dari pengaturan server.
4. Baca temuan dan unduh laporan yang dibuat otomatis.

AI setup dilakukan satu kali. Satu runtime dapat dipilih secara eksplisit
untuk semua peran audit; validasi tetap berjalan dalam sesi terpisah.

## Cakupan pemeriksaan

| Permukaan | Yang diperiksa | Hasil |
|---|---|---|
| Login dan akun | Isian wajib, pengelolaan sesi, ganti kata sandi | Kredensial login tetap diperlukan; rincian admin tidak ditampilkan ke viewer |
| Overview | Aksi awal dan kondisi belum ada proyek | New audit membuka pembuatan proyek saat belum ada proyek |
| Projects | Pemilihan folder, nama, scope, otorisasi, impor | Pemilih folder host, nama otomatis, scope lanjutan, impor otomatis |
| Audit creation | Pilihan awal, snapshot, limit, mulai sekarang, workspace | Tidak perlu mengatur parameter untuk satu proyek; pilihan teknis dilipat |
| Audit detail | Tugas, keputusan, pembatalan, provenance | Operasi berjalan ditampilkan dari server; konfirmasi pembatalan tetap ada |
| AI setup | Deteksi CLI, provider/model, pengikatan peran, tes berbayar | Satu tombol untuk semua peran; tes dan rincian teknis di bagian lanjutan |
| Agents | Peran yang digunakan, isian teknis, kontrol yang tidak bekerja | Empat peran audit utama; editor awal hanya runtime dan model |
| Skills | Deteksi, pencarian, pemberian akses, pemakaian | Deteksi otomatis sudah tersedia; pemberian akses tetap eksplisit |
| MCP | Deteksi, enablement, keterkaitan skill, pemakaian | Tidak diwajibkan untuk audit biasa; akses eksternal tetap opt-in |
| Explorer | Penelusuran source dan akses berkas | Tetap tersedia di Advanced tools; pembatasan snapshot/scope dipertahankan |
| Tasks | Status, retry, log, error, approval | Tetap tersedia di Advanced tools dan halaman audit |
| Approvals | Kapan approval diperlukan | Audit baca saja tidak memerlukan approval; akses shell/write tetap memerlukannya |
| Findings | Filter, bukti, retest | Bukti dan sesi independen tetap diperlukan; tidak ada langkah setup baru |
| Reports | Format unduhan, regenerasi, hash, catatan teknis | Unduhan tetap langsung; detail dan riwayat dilipat |
| Settings | Nilai bawaan, perubahan sebagian, konfirmasi, kredensial, pengguna | Tiga pengaturan umum; hanya perubahan yang dikirim |
| API dan orchestrator | Prasyarat impor, role/CSRF, snapshot, pemilihan runtime | Prasyarat yang bisa diotomatisasi dipenuhi oleh alur UI; kontrol akses tetap berlaku |

## Hambatan yang diperbaiki

| Temuan | Dampak sebelumnya | Perbaikan |
|---|---|---|
| Kolom pemberi izin dan referensi wajib | Pembuatan proyek berhenti sebelum pengguna dapat mulai | Tidak diminta di UI; metadata lama tetap kompatibel dan tidak dipalsukan |
| Path harus diketik dan root diatur manual | Folder yang ada ditolak; pengguna harus mengedit environment | Deteksi home/lokasi proyek/volume bawaan dan pemilih folder; konfigurasi khusus admin tetap dihormati |
| Impor proyek adalah langkah terpisah | Pengguna harus mencari aksi berikutnya | Pembuatan proyek langsung mengimpor snapshot |
| Audit menolak proyek yang belum diimpor | Pengguna diminta kembali ke halaman lain | Snapshot dibuat otomatis sebelum audit bila belum ada |
| Sepuluh kontrol pada formulir audit awal | Pengguna harus memahami detail orkestrasi sebelum mulai | Nol kontrol konfigurasi awal untuk satu proyek, atau satu pemilih proyek bila ada beberapa |
| Nilai UI menimpa default server | Konfigurasi admin tidak dipakai meskipun pengguna tidak mengubah apa pun | UI mewarisi default server dan hanya mengirim override yang diubah |
| Start gagal setelah audit tersimpan | Form terlihat gagal total dan bisa menghasilkan audit ganda saat dicoba lagi | Pengguna diarahkan ke audit tersimpan agar bisa melanjutkan dari sana |
| Tiga belas tujuan navigasi tampil sekaligus | Fitur teknis bersaing dengan pekerjaan utama | Enam tujuan utama; tujuh lainnya di Advanced tools, terbuka otomatis untuk route aktif |
| Satu runtime harus diatur pada beberapa peran | Pengguna harus memahami setiap peran agar satu CLI dapat dipakai | Use for audits mengatur empat peran sekaligus, memakai model default dan seluruh daftar tool runtime; perubahan tool berikutnya otomatis diwarisi |
| Tes runtime berbayar menjadi aksi utama | Check, Test, dan Configure terlihat sama penting | Penetapan runtime menjadi aksi utama; tes panggilan model berada di Technical details |
| Tiga belas pengaturan eksekusi tampil sekaligus | Pengguna harus menghadapi policy, timeout, sandbox, dan cap yang jarang diubah | Tiga pengaturan umum; sepuluh pengaturan teknis di Advanced execution settings |
| Menyimpan pengaturan mengirim semua nilai | Konfirmasi shell/write muncul lagi meskipun tidak diubah | Hanya nilai berubah yang dikirim; API meminta konfirmasi hanya pada transisi nonaktif ke aktif |
| Kontrol concurrency per peran tidak tersimpan | UI memberi kesan perubahan sudah diterapkan | Kontrol nonfungsional dihapus; batas peran yang tersimpan tetap ditampilkan sebagai informasi |
| Provider kredensial wajib diketik untuk setiap variabel | Detail teknis menjadi prasyarat menambah secret | Scope default global; pembatasan provider bersifat opsional |
| Capability, hash, riwayat, dan uraian internal memenuhi halaman | Pengguna harus menyaring banyak detail untuk mencari aksi utama | Rincian dipindahkan ke bagian yang dapat dibuka saat diperlukan |
| Settings meminta data admin untuk viewer | Request ditolak lalu error disembunyikan | Request admin tidak dibuat untuk akun non-admin |
| Daftar tool runtime kosong diganti default diam-diam | Konfigurasi kosong tidak benar-benar dihormati | Daftar kosong dipertahankan sampai adapter; tidak mengaktifkan tool bawaan secara diam-diam |
| Runtime mengizinkan 9 tool tetapi agent tetap memakai 4 | Daftar peran lama dan tombol penetapan memotong izin pengguna | Peran mengikuti tool runtime secara otomatis; UI menampilkan jumlah dan sumber daftar yang benar; pembatasan peran khusus tetap opsional |
| Isian invalid tersembunyi di bagian lanjutan | Browser tidak dapat memfokuskan field yang perlu diperbaiki | Bagian lanjutan dibuka otomatis ketika validasi native gagal |

Sebagian perbaikan proyek dan folder sudah dimulai pada perubahan sebelumnya;
audit ini meninjau serta melanjutkan alur tersebut sampai audit dan laporan.

## Aturan yang tetap diperlukan

Aturan berikut memiliki fungsi nyata dan tidak perlu dijadikan pilihan saat
menjalankan audit biasa:

- Login, role, dan CSRF melindungi workspace serta operasi server.
- Folder kanonik, snapshot, dan scope membatasi berkas yang diterima agent.
- Sesi discovery tidak boleh mengesahkan temuannya sendiri.
- Kutipan source harus cocok dengan snapshot agar temuan tidak dibuat-buat.
- Batas biaya, waktu, dan concurrency mencegah pekerjaan berjalan tanpa batas.
- Akses shell/write dan MCP tetap memerlukan pemberian akses yang sesuai.
- Penghapusan kredensial, penonaktifan akun, dan pembatalan kerja berjalan
  tetap memerlukan keputusan yang disengaja.

Pemangkasan dilakukan pada langkah manual, pilihan awal, kontrol yang tidak
berfungsi, dan konfirmasi berulang. Aturan integritas bukti dan akses tidak
perlu dihapus untuk menghasilkan alur biasa yang lebih singkat.

## Verifikasi

Hasil lokal setelah perbaikan pewarisan tool: **119 tes lulus, 0 gagal**; typecheck, build, dan pemeriksaan shell
lulus. Pemeriksaan browser mencakup 13 route pada empat ukuran layar, alur
formulir utama, serta perilaku akun viewer. Pemindaian mekanis Impeccable
menghasilkan 0 temuan.

- `bun run check`: typecheck dan seluruh test suite.
- `bun run build` dan `bash -n install.sh start.sh`.
- `bun run scripts/check-usability-ui.ts`: alur proyek sampai audit,
  pemulihan kegagalan start, perubahan settings, konfirmasi pertama kali,
  kredensial, penetapan runtime, perubahan tool yang otomatis diwarisi empat peran,
  field lanjutan, serta semua 13 route pada
  lebar 320, 768, 1024, dan 1440 piksel. Script memakai server/data sementara
  dan CLI pengujian; tidak memanggil model.
- Pemeriksaan visual dan keyboard pada formulir serta halaman yang berubah.

Audit ini menilai UI yang tersedia, kode penanganan API, dan pengujian lokal.
Ini bukan pengukuran kepuasan pengguna nyata atau uji kredensial provider produksi.
