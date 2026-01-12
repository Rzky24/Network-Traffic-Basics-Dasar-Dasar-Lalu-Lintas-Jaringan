# Network-Traffic-Basics / Dasar-Dasar-Lalu-Lintas-Jaringan
Analisis Lalu Lintas Jaringan (Network Traffic Analysis/ NTA ) adalah proses yang mencakup pengambilan, pemeriksaan, dan analisis data saat mengalir dalam jaringan. Tujuannya adalah untuk mendapatkan visibilitas lengkap dan memahami apa yang dikomunikasikan di dalam dan di luar jaringan. Penting untuk ditekankan bahwa NTA bukanlah sinonim untuk alat Wireshark. Lebih dari itu: NTA merupakan kombinasi dari korelasi beberapa log, inspeksi paket mendalam, dan statistik aliran jaringan dengan tujuan spesifik yang telah diuraikan (yang akan kita bahas nanti).

Kemampuan menganalisis lalu lintas jaringan adalah keterampilan penting, tidak hanya untuk calon analis SOC L1 tetapi juga untuk banyak peran tim biru dan merah lainnya. Sebagai analis L1, Anda perlu mampu menavigasi lautan informasi jaringan dan memahami apa yang normal dan apa yang menyimpang dari standar.

Di ruangan ini, kita akan fokus pada definisi analisis lalu lintas jaringan, mengapa Anda membutuhkannya, apa dan bagaimana Anda dapat mengamati lalu lintas jaringan, serta beberapa sumber dan aliran lalu lintas jaringan yang perlu Anda ketahui.

Tujuan pembelajaran
Pahami apa itu analisis lalu lintas jaringan.
Ketahui apa yang dapat diamati.
Ketahui cara mengamati lalu lintas jaringan.
Pahami sumber dan aliran lalu lintas jaringan yang umum.

# Apa tujuan dari analisis lalu lintas jaringan?
Mengapa kita perlu menganalisis lalu lintas jaringan? Sebelum menjawab pertanyaan ini, mari kita lihat skenario berikut.

Tunneling dan Beaconing DNS
Anda adalah seorang analis SOC , dan Anda menerima peringatan yang menyatakan bahwa sejumlah besar kueri DNS berasal dari host bernama WIN-016 dengan IP 192.168.1.16. Log DNS pada firewall menunjukkan beberapa kueri DNS menuju TLD yang sama, setiap kali menggunakan subdomain yang berbeda.
2025-10-03 09:15:23    SRC=192.168.1.16      QUERY=aj39skdm.malicious-tld.com    QTYPE=A      
2025-10-03 09:15:31    SRC=192.168.1.16      QUERY=msd91azx.malicious-tld.com    QTYPE=A     
2025-10-03 09:15:45    SRC=192.168.1.16      QUERY=cmd01.malicious-tld.com       QTYPE=TXT     
2025-10-03 09:15:45    SRC=192.168.1.16      QUERY=cmd01.malicious-tld.com       QTYPE=TXT     
Berdasarkan log DNS, kita dapat mengambil informasi berikut:

Kueri dan tipe kueri
Subdomain dan domain tingkat atas: Kita dapat memeriksa alat seperti abuseDB atau VirusTotal untuk memeriksa apakah domain tersebut berbahaya.
IP Host: Kita dapat mengidentifikasi sistem yang mengirimkan permintaan DNS.
IP Tujuan: Kita dapat menggunakan alat seperti  AbuseIPDB atau VirusTotal untuk memverifikasi apakah IP tersebut ditandai sebagai berbahaya.
Cap waktu: Kita dapat membuat garis waktu yang memetakan berbagai kueri mencurigakan.
Log DNS tidak berisi informasi lebih dari itu, sehingga sulit untuk menarik kesimpulan hanya berdasarkan informasi tersebut. Kita perlu memeriksa lalu lintas DNS lebih teliti dan mengecek isi dari kueri dan balasan DNS. Hal ini akan memungkinkan kita untuk menentukan sifat dari kueri dan balasan tersebut. 

Skenario ini adalah contoh utama mengapa kita membutuhkan analisis lalu lintas jaringan. Firewall dan perangkat lain mencatat permintaan DNS dan responsnya, tetapi bukan isinya. Pelaku ancaman, misalnya, dapat menggunakan catatan TXT untuk mengirim instruksi Perintah dan Kontrol ke sistem yang disusupi. Kita dapat menemukan ini dengan memeriksa isi permintaan DNS. Fragmen tangkapan paket di bawah ini menunjukkan isi balasan DNS yang berisi perintah C2.

Domain Name System (response)
    Transaction ID: 0x4a2b
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .... .... .... 0000 = RCODE: No error (0)
    Questions: 1
    Answer RRs: 1
    Authority RRs: 0
    Additional RRs: 0
    Queries
        cmd1.evilc2.com: type TXT, class IN
    Answers
        cmd1.evilc2.com: type TXT, class IN, TTL 60, TXT length: 20
            TXT: "SSBsb3ZlIHlvdXIgY3VyaW91c2l0eQ=="

Mengapa kita perlu menganalisis lalu lintas jaringan?
Secara umum, kita akan menggunakan analisis lalu lintas jaringan untuk:

Pantau kinerja jaringan.
Periksa adanya anomali pada jaringan. Misalnya, lonjakan kinerja yang tiba-tiba, jaringan lambat, dll.
Periksa isi komunikasi yang mencurigakan secara internal dan eksternal. Misalnya, eksfiltrasi melalui DNS , pengunduhan file ZIP berbahaya melalui HTTP , pergerakan lateral, dll.
Dari perspektif SOC , analisis lalu lintas jaringan membantu:

Mendeteksi aktivitas yang mencurigakan atau berbahaya
Merekonstruksi serangan selama respons insiden
Memverifikasi dan memvalidasi peringatan
Berikut adalah dua skenario lagi yang menggambarkan pentingnya analisis lalu lintas jaringan:

Berdasarkan log sistem pengguna akhir, sistem tersebut mulai menyimpang dari perilaku normalnya sekitar pukul 4 sore UTC . Menganalisis lalu lintas jaringan yang masuk dan keluar dari sistem ini, kami menemukan permintaan HTTP yang mencurigakan dan berhasil mengekstrak file ZIP yang mencurigakan.
Kami menerima peringatan bahwa sistem pengguna akhir mengirimkan banyak permintaan DNS dibandingkan dengan standar jaringan. Setelah memeriksa permintaan DNS , kami menemukan bahwa data dieksfiltrasi menggunakan teknik yang disebut tunneling DNS.
Sekarang setelah kita mengetahui mengapa kita membutuhkan analisis lalu lintas jaringan, mari kita lanjutkan dengan tugas berikutnya untuk mengetahui apa sebenarnya yang dapat kita pantau.

# Lalu Lintas Jaringan Apa yang Dapat Kita Amati?
Cara terbaik untuk menampilkan lalu lintas yang dapat kita amati di jaringan adalah dengan menggunakan arsitektur yang diterapkan di hampir setiap perangkat dengan antarmuka jaringan: tumpukan TCP /IP. Gambar di bawah menunjukkan berbagai lapisan model TCP /IP. Setiap lapisan menjelaskan informasi yang dibutuhkan (header) untuk meneruskan data ke lapisan berikutnya. Informasi yang termasuk dalam setiap header, bersama dengan data aplikasi, adalah persis apa yang ingin kita amati. Log sering kali menyertakan sebagian kecil dari header ini, tetapi tidak pernah detail paket lengkap. Inilah mengapa kita perlu melakukan analisis lalu lintas jaringan.
<img width="1370" height="457" alt="image" src="https://github.com/user-attachments/assets/27958357-a50a-4e4f-9f29-bb1207be430c" />
# Aplikasi
Pada lapisan aplikasi, kita dapat menemukan dua struktur informasi penting: informasi header aplikasi dan data aplikasi itu sendiri (payload). Informasi ini akan berubah tergantung pada protokol lapisan aplikasi yang digunakan. Mari kita lihat contoh HTTP .

Cuplikan kode di bawah ini menunjukkan header aplikasi dari klien yang mengirimkan permintaan GET dan respons server. Sebagian besar proxy web dan firewall mencatat data header ini. Yang tidak mereka catat adalah data aplikasi atau payload. Dari permintaan GET, Anda dapat menentukan bahwa klien meminta file bernama suspicious_package.zip. Respons server mencakup kode 200, yang berarti permintaan diterima. Namun, yang tidak dapat Anda lihat dalam log adalah isi file ZIP (ditandai dengan warna kuning).

Permintaan
GET /downloads/suspicious_package.zip HTTP/1.1
Host: www.tryhackrne.thn
User-Agent: curl/7.85.0
Accept: */*
Connection: close

Tanggapan/Respon
HTTP/1.1 200 OK
Date: Mon, 29 Sep 2025 10:15:30 GMT
Server: nginx/1.18.0
Content-Type: application/zip
Content-Length: 10485760
Content-Disposition: attachment; filename="suspicious_package.zip"
Last-Modified: Mon, 29 Sep 2025 09:54:00 GMT
ETag: "5d8c72-9f8a1c-3a2b4c"
Accept-Ranges: bytes
Connection: close
[binary ZIP file bytes follow — 10,485,760 bytes]

# Transport
Data dan header aplikasi disegmentasikan dan dienkapsulasi pada lapisan transport menjadi bagian-bagian yang lebih kecil. Setiap bagian menyertakan header transport, dalam kebanyakan kasus TCP atau UDP. Mari kita lihat entri log firewall di bawah ini:

2025-10-13 09:15:32 ACCEPT TCP src=192.168.1.45 dst=172.217.22.14 sport=51432 dport=443 flags=SYN len=60
2025-10-13 09:15:32 ACCEPT TCP src=172.217.22.14 dst=192.168.1.45 sport=443 dport=51432 flags=SYN,ACK len=60

# Log firewall sering kali menyertakan port sumber dan tujuan serta flag, tetapi semua field lainnya seringkali tidak disertakan. Namun, log tersebut berharga untuk mendeteksi jenis serangan tertentu, seperti pembajakan sesi. Pembajakan sesi dapat dideteksi dengan menganalisis nomor urutan yang terdapat dalam header. Jika nomor urutan tiba-tiba berjauhan, penyelidikan lebih lanjut diperlukan. Output di bawah ini menunjukkan serangkaian paket yang ditangkap dengan Wireshark. 

No.     Time        Source          Destination     Protocol Length  Info
1       0.000000    192.168.1.45    172.217.22.14   TCP      74      51432 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
2       0.000120    172.217.22.14   192.168.1.45    TCP      74      80 → 51432 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460
3       0.000220    192.168.1.45    172.217.22.14   TCP      66      51432 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0
4       0.010500    192.168.1.45    172.217.22.14   TCP      1514    51432 → 80 [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=1460
5       0.010620    172.217.22.14   192.168.1.45    TCP      66      80 → 51432 [ACK] Seq=1 Ack=1461 Win=65535 Len=0
6       0.020100    192.168.99.200  172.217.22.14   TCP      74      51432 → 80 [PSH, ACK] Seq=34567232 Ack=1 Win=64240 Len=20  

Tiga baris pertama menunjukkan jabat tangan tiga arah TCP normal.
Baris 4 dan 5 menunjukkan transfer data yang sah.
Baris 6 menunjukkan paket dari sumber lain yang mencoba menyusup ke dalam sesi. Perhatikan lonjakan besar pada nomor urutnya.

# Internet
Ketika lapisan transport mengirimkan sebuah segmen, lapisan internet juga menambahkan header-nya. Jika segmen tersebut lebih besar dari Maximum Transmission Unit (MTU), segmen tersebut akan dibagi menjadi beberapa fragmen, dan header akan ditambahkan ke masing-masing fragmen. Bidang yang paling sering dicatat adalah IP sumber dan tujuan serta TTL. Ini sudah cukup untuk sebagian besar kasus penggunaan. Namun, jika kita ingin, misalnya, mendeteksi serangan fragmentasi, kita perlu memeriksa bidang offset fragmen dan panjang total juga. Ada berbagai variasi serangan fragmentasi. Misalnya, penyerang dapat membuat fragmen kecil untuk menghindari IDS atau mengacaukan penyusunan kembali fragmen dengan menggunakan rentang byte yang tumpang tindih. Contoh di bawah ini menunjukkan rentang byte yang tumpang tindih. Offset pada baris 3 (ditandai dengan warna kuning) tumpang tindih dengan offset pada baris 2. Ini berarti bahwa paket lengkap dapat disusun kembali dengan satu atau lain cara. Penyerang dapat menggunakan teknik ini untuk melewati IDS, misalnya.

No.   Time       Source        Destination   Protocol Length Info
1     0.000000   203.0.113.45  192.168.1.10  UDP      1514    Fragmented IP protocol (UDP) (id=0x1a2b) [MF] Offset=0, Len=1480
2     0.000015   203.0.113.45  192.168.1.10  UDP      1514    Fragmented IP protocol (UDP) (id=0x1a2b) [MF] Offset=1480, Len=1480
3     0.000030   203.0.113.45  192.168.1.10  UDP       600    Fragmented IP protocol (UDP) (id=0x1a2b) Offset=1480, Len=64   <-- Overlap
4     0.000045   192.168.1.10  203.0.113.45  ICMP      98     Destination unreachable (Fragment reassembly time exceeded)

# Setelah lapisan internet menyelesaikan enkapsulasi, paket IP dikirim ke lapisan tautan. Lapisan tautan juga menambahkan header-nya, yang berisi informasi pengalamatan lebih lanjut. Sebagian besar log akan menampilkan alamat MAC sumber dan tujuan. Untuk
jenis serangan tertentu, misalnya, ARP poisoning atau spoofing, informasi dalam log tidak akan cukup. Untuk jenis serangan ini, kita membutuhkan paket lengkap dan konteksnya. Misalnya, yang tidak dapat Anda lihat dalam log adalah ketika alamat MAC muncul dari beberapa antarmuka atau ketika banyak paket ARP yang tidak perlu dikirim dengan alamat MAC yang saling bertentangan. Contoh di bawah ini menunjukkan tangkapan paket yang merinci serangan ARP poisoning. Host dengan IP 192.168.1.200 membalas setiap permintaan ARP dengan MAC yang sama.

No.   Time       Source           Destination      Protocol Length Info
1     0.000000   192.168.1.1      Broadcast        ARP      60     Who has 192.168.1.10? Tell 192.168.1.1
2     0.000025   192.168.1.10     192.168.1.1      ARP      60     192.168.1.10 is at 00:11:22:33:44:55
3     1.002010   192.168.1.200    192.168.1.1      ARP      60     192.168.1.10 is at aa:bb:cc:dd:ee:ff  <-- Attacker spoof
4     1.002015   192.168.1.200    192.168.1.10     ARP      60     192.168.1.1 is at aa:bb:cc:dd:ee:ff  <-- Attacker spoof
5     1.100000   192.168.1.10     172.217.22.14    TCP      74     54433 → 80 [SYN] Seq=0 Win=64240 Len=0
6     1.100120   192.168.1.200    172.217.22.14    TCP      74     54433 → 80 [SYN] Seq=0 Win=64240 Len=0  <-- Relayed via attacker

Jawablah pertanyaan-pertanyaan di bawah ini.
Perhatikan contoh HTTP dalam tugas dan jawab pertanyaan berikut: Berapa ukuran lampiran ZIP yang disertakan dalam respons HTTP? Catat jawabannya dalam byte? 10485760
Serangan apa yang digunakan penyerang untuk mencoba menghindari IDS?
fragmentation
Kolom mana di header TCP yang dapat kita gunakan untuk mendeteksi pembajakan sesi?
sequence number





