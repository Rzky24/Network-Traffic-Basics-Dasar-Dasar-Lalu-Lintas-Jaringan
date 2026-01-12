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

# Response/ Tanggapan
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

Log firewall sering kali menyertakan port sumber dan tujuan serta flag, tetapi semua field lainnya seringkali tidak disertakan. Namun, log tersebut berharga untuk mendeteksi jenis serangan tertentu, seperti pembajakan sesi. Pembajakan sesi dapat dideteksi dengan menganalisis nomor urutan yang terdapat dalam header. Jika nomor urutan tiba-tiba berjauhan, penyelidikan lebih lanjut diperlukan. Output di bawah ini menunjukkan serangkaian paket yang ditangkap dengan Wireshark. 

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

# LINK 
Setelah lapisan internet menyelesaikan enkapsulasi, paket IP dikirim ke lapisan tautan. Lapisan tautan juga menambahkan header-nya, yang berisi informasi pengalamatan lebih lanjut. Sebagian besar log akan menampilkan alamat MAC sumber dan tujuan. Untuk
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

Sumber dan Aliran Lalu Lintas Jaringan
Pada tugas sebelumnya, kita telah membahas apa yang dapat kita amati secara teoritis berdasarkan tumpukan TCP /IP. Secara praktis, akan lebih bermanfaat untuk fokus pada sumber dan aliran spesifik. Jaringan perusahaan biasanya memiliki beberapa aliran dan sumber jaringan yang telah ditentukan sebelumnya. Kita dapat mengelompokkan sumber-sumber tersebut menjadi dua kategori:

Perantara
Titik akhir
Alur tersebut juga dapat kita kelompokkan menjadi dua kategori:

Utara-Selatan: Lalu lintas yang keluar atau masuk ke LAN dan melewati firewall.
Timur-Barat: Lalu lintas yang tetap berada di dalam LAN (termasuk LAN yang meluas ke cloud)
Mari kita bahas satu per satu di bawah ini.

# Sumber
Seperti yang telah disebutkan, terdapat dua sumber lalu lintas jaringan: perangkat ujung (endpoint) dan perangkat perantara (intermediary). Perangkat-perangkat ini dapat ditemukan di dalam LAN dan WAN.

#Sumber Perantara
Ini adalah perangkat yang sebagian besar dilewati oleh lalu lintas. Meskipun menghasilkan beberapa lalu lintas, jumlahnya jauh lebih rendah daripada yang dihasilkan oleh perangkat titik akhir. Di bawah kategori ini, kita dapat menemukan firewall, switch, proxy web, IDS , IPS , router, titik akses, pengontrol LAN nirkabel, dan banyak lagi. Mungkin kurang relevan bagi kita, tetapi semua infrastruktur Penyedia Layanan Internet juga dianggap sebagai bagian dari kategori ini.

Lalu lintas yang berasal dari perangkat ini berasal dari layanan seperti protokol perutean (EIGRP, OSPF, BGP), protokol manajemen (SNMP, PING), protokol pencatatan (SYSLOG), dan protokol pendukung lainnya ( ARP , STP, DHCP ).

#Sumber Titik Akhir (Endpoint Sources)
: Ini adalah perangkat tempat lalu lintas berasal dan berakhir. Perangkat titik akhir menggunakan sebagian besar bandwidth jaringan. Perangkat yang termasuk dalam kategori ini adalah server, host, perangkat IoT , printer, mesin virtual, sumber daya cloud, ponsel, tablet, dan masih banyak lagi.

# Arus
Alur lalu lintas jaringan biasanya ditentukan oleh layanan yang tersedia di jaringan, seperti Active Directory, SMB , HTTPS, dan sebagainya. Dalam jaringan perusahaan pada umumnya, kita dapat mengelompokkan alur ini menjadi lalu lintas Utara-Selatan dan Timur-Barat.

Lalu Lintas Utara-Selatan (North-South Traffic
/NS) sering dipantau secara ketat karena mengalir dari LAN ke WAN dan sebaliknya. Layanan yang paling terkenal dalam kategori ini adalah protokol klien-server seperti HTTPS, DNS , SSH , VPN , SMTP , RDP , dan banyak lagi. Setiap protokol ini memiliki dua aliran: masuk (inbound) dan keluar (egress). Semua lalu lintas ini melewati firewall dengan satu atau lain cara. Mengkonfigurasi aturan firewall dan pencatatan log dengan benar adalah kunci untuk visibilitas.

Lalu Lintas Timur-Barat (East-West Traffic
/EW) tetap berada di dalam LAN perusahaan, sehingga seringkali kurang dipantau. Namun, penting untuk melacak aliran data ini. Ketika jaringan disusupi, penyerang seringkali akan mengeksploitasi berbagai layanan internal untuk bergerak secara lateral di dalam jaringan. Seperti yang kita lihat di bawah ini, ada banyak layanan dalam kategori ini. Klik pada setiap kategori untuk melihat layanan apa saja yang terdapat di dalamnya.

Layanan Direktori, Otentikasi & Identitas
Layanan berbagi file & pencetakan
Layanan router, switching, dan infrastruktur
Komunikasi Aplikasi
Pencadangan & Replikasi
Pemantauan & Manajemen
 

# Contoh Alur
Mari kita lihat secara visual beberapa alur jaringan yang disebutkan di atas.

# HTTPS
Terdapat berbagai variasi alur lalu lintas jaringan HTTPS. Mari kita periksa alur di mana proksi web melakukan inspeksi TLS
: Sebuah host meminta situs web; permintaan ini dikirim ke NGFW, yang mencakup proksi web. Proksi web akan bertindak sebagai server web dan secara bersamaan membangun sesi TCP baru dengan server web sebenarnya dan meneruskan permintaan klien. Ketika proksi web menerima jawaban dari server web, ia memeriksa isinya dan kemudian meneruskannya ke host jika dianggap aman. Singkatnya, kita memiliki dua sesi, satu antara klien dan proksi dan yang lainnya antara proksi dan server web. Dari sudut pandang klien, ia telah membangun sesi dengan server web.


<img width="1210" height="212" alt="image" src="https://github.com/user-attachments/assets/ffa118ad-f40f-4912-a815-c4ef4bd69f62" />

# Lalu lintas DNS eksternal di dalam jaringan perusahaan dimulai ketika sebuah host mengirimkan permintaan DNS . Host mengirimkan permintaan tersebut ke server DNS internal
pada port 53, yang kemudian akan bertindak atas nama host. Pertama, server akan memeriksa apakah ia memiliki jawaban atas permintaan tersebut dalam cache-nya; jika tidak, ia akan mengirimkan permintaan tersebut melalui router, melewati firewall , ke server DNS yang telah dikonfigurasi . Jawaban tersebut kemudian akan mengikuti jalur yang sama ke server DNS internal , yang kemudian akan meneruskannya ke host. Diagram jaringan di bawah ini menunjukkan alur yang disederhanakan

<img width="1030" height="350" alt="image" src="https://github.com/user-attachments/assets/0d0132a4-c533-49a9-91c8-1a5237fd9ca4" />

# SMB dengan Kerberos
Ketika sebuah host membuka share ke, misalnya, \\FILESERVER\MARKETING, sebuah sesi SMB akan dibuat. Pertama, autentikasi dilakukan melalui Kerberos . Ketika pengguna masuk ke host, ia melakukan autentikasi dengan Key Distribution Center pada Domain Controller dan menerima Ticket Granting Ticket untuk meminta "tiket autentikasi layanan" . Sekarang, host meminta tiket layanan menggunakan Ticket Granting Ticket yang diterimanya sebelumnya. Host kemudian menggunakan tiket ini untuk membangun koneksi SMB . Setelah sesi SMB dibuat, host dapat mengakses share tersebut. Di bawah ini kita melihat diagram jaringan yang disederhanakan dari alur tersebut.

<img width="1060" height="510" alt="image" src="https://github.com/user-attachments/assets/a29329de-8265-41b6-859a-d68fb6206ed0" />

Jawablah pertanyaan-pertanyaan di bawah ini.
Kategori perangkat manakah yang menghasilkan lalu lintas terbanyak dalam jaringan?
endpoint
Sebelum sesi SMB dapat dibuat, layanan mana yang perlu dihubungi terlebih dahulu untuk otentikasi?
kerberos
TLS itu singkatan dari apa?
Transport Layer Security

Bagaimana Kita Dapat Mengamati Lalu Lintas Jaringan?

Lihat Situs
Setelah membahas apa yang dapat dan harus kita amati dalam sebuah jaringan, mari kita periksa caranya. Seperti yang disebutkan dalam pendahuluan, analisis lalu lintas jaringan berfokus pada penggabungan berbagai sumber informasi, menganalisisnya, menemukan pola, dan menggunakan hasilnya untuk menginformasikan tindakan.

Kita dapat memperoleh sumber informasi ini dengan berbagai cara:

Log
Pengambilan Paket Lengkap
Statistik Jaringan
Log
Log adalah langkah pertama kita untuk memperoleh informasi tentang apa yang terjadi di jaringan. Setiap sistem dan protokol dalam jaringan memiliki cara untuk mencatat informasi. Penting untuk diketahui bahwa tidak ada standar universal untuk mengimplementasikan pencatatan pada setiap sistem dan protokol. Setiap vendor memilih cara mengimplementasikan pencatatan untuk diri mereka sendiri. Misalnya, Microsoft mengimplementasikan Windows Event Logs. Selain itu, data yang dicatat bergantung pada vendor. Sebagian besar vendor tidak akan mencatat paket lengkap saat masuk atau keluar dari sistem. Mereka akan mencatat beberapa bidang yang mereka anggap berguna, seperti alamat IP sumber dan alamat IP tujuan. Pada terminal di bawah ini, kita melihat beberapa contoh log otentikasi pada host Linux menggunakan format Syslog dan log akses server web Apache yang menggunakan standar CLF.

# Auth log
Oct  8 11:20:15 web01 sshd[2145]: Accepted password for gensane from 192.168.1.50 port 52234 ssh2

# Apache web server access log
192.168.1.50 - - [08/Oct/2025:11:20:18 +0200] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"

Meskipun tidak ada cara pencatatan standar, ada beberapa protokol yang menawarkan cara standar untuk mengirim pesan log dari perangkat ke pengumpul data, misalnya, Syslog dan SNMP.

Ketika log tidak memberikan informasi yang cukup, kita harus menggali lebih dalam. Untuk melakukannya, kita perlu mengkorelasikan log, memeriksa tangkapan paket lengkap, dan mengecek statistik jaringan.

Pengambilan Paket Lengkap
Pada tugas ketiga, kita telah membahas seperti apa tampilan sebuah paket lengkap. Sekarang, kita ingin mengetahui cara menangkap dan memeriksa paket-paket tersebut. Untuk melakukan ini, kita memiliki dua pilihan:

Pasang network tap fisik.
Konfigurasi pencermian port
Network Tap
adalah perangkat fisik yang Anda tempatkan secara inline di jaringan Anda. Perangkat ini membuat salinan semua lalu lintas jaringan yang lewat tanpa memengaruhi kinerja. Data yang disalin tersebut kemudian diteruskan ke kotak penangkap paket, IDS, atau sistem lain menggunakan port pemantauan khusus. Menarik untuk diketahui bahwa TAP hanya beroperasi pada lapisan tautan model TCP-IP; ia tidak memerlukan alamat MAC atau IP, karena ia menyalin sinyal listrik/cahaya dan mengirimkannya ke port pemantauannya. Dengan cara ini, tidak ada penundaan tambahan pada jaringan. Gambar di bawah menunjukkan contoh network TAP. <img width="824" height="552" alt="image" src="https://github.com/user-attachments/assets/8e6db3da-4086-405b-8a39-0a6cd4bfb60c" />

Pencermian Port (
Port Mirroring) Pencermian port adalah pendekatan perangkat lunak untuk menyalin paket dari satu port pada perangkat perantara ke port lain yang terhubung ke, misalnya, IDS, kotak penangkap paket, atau sistem lain. Setiap vendor memiliki nama sendiri. Cisco, misalnya, menyebutnya SPAN. Pada terminal di bawah ini, kita dapat melihat cara mengkonfigurasi SPAN pada perangkat Cisco. Dalam contoh ini, paket yang melewatinya fastEthernet0/1diduplikasi dan dikirim ke fastEthernet0/2.

Switch(config)# monitor session 1 source interface fastEthernet0/1
Switch(config)# monitor session 1 destination interface fastEthernet0/2

Gambar di bawah menunjukkan seperti apa tampilannya. WIN-001 mengirimkan paket melalui switch untuk berkomunikasi dengan server. Ketika paket tiba di switch, paket tersebut diduplikasi dan juga dikirim ke perangkat pemantauan.

<img width="463" height="347" alt="image" src="https://github.com/user-attachments/assets/66cde53e-2a51-4e9e-bb47-0ab092d53ef9" />

Perlu dicatat bahwa perangkat perantara tidak harus berupa perangkat fisik, pencermian port juga dapat dikonfigurasi pada perangkat virtual seperti VMware vSwitch. Lingkungan cloud juga memiliki layanan khusus yang menawarkan pencermian. AWS, misalnya, menawarkan VPC Traffic Mirroring.

Praktik Terbaik
Saat melakukan pengambilan paket data secara lengkap, kita perlu mempertimbangkan beberapa hal:

Penempatan: Tergantung pada lalu lintas mana yang ingin kita tangkap, kita perlu menempatkan TAP atau mengkonfigurasi mirror di tempat yang tepat.
Durasi: Pengambilan paket data secara penuh akan membutuhkan jumlah penyimpanan yang proporsional. Jika Anda menangkap lalu lintas pada jalur 1 Gbps selama seharian penuh, kita akan membutuhkan rata-rata 10,8 TB ruang penyimpanan. Bayangkan jumlah penyimpanan yang kita butuhkan pada jalur 10 Gbps atau 40 Gbps.
Mirror vs TAP: Tap fisik hampir tidak mengurangi performa. Mirroring dapat memengaruhi performa ketika sejumlah besar lalu lintas melewati port yang di-mirroring.

Exercise: Open the static site and complete the two exercises by placing the tap in the correct position and uncovering the flag in the traffic. Fill in the flags at the end of this task. You can open the static site by clicking on the "View Site" button and the top of this task. The static site will open in split-screen. To open the static site in full screen, click the "Full Screen" button on the static site.

Alat-alat
Sekarang setelah kita mengetahui cara melakukan pengambilan paket lengkap, mari kita lihat alat-alat yang tersedia untuk menganalisis paket-paket ini:

Wireshark
TCPdump
Sistem IPS / IDS seperti Snort, Suricata, dan Zeek.
Ini adalah beberapa dari banyak alat yang tersedia untuk menganalisis tangkapan paket lengkap. Di ruangan-ruangan selanjutnya dalam modul ini, kita akan fokus pada penggunaan Wireshark.

Statistik Jaringan
Cara hebat lainnya untuk menemukan anomali di jaringan Anda adalah dengan mengumpulkan metadata tentang data yang mengalir melalui jaringan, seperti menghitung jumlah permintaan DNS yang dikirimkan oleh sebuah host. Beberapa protokol memfasilitasi hal ini. Kita akan membahas secara singkat dua di antaranya: NetFlow dan IPFIX .

NetFlow adalah protokol yang dikembangkan oleh Cisco yang mengumpulkan metadata tentang lalu lintas yang mengalir dalam jaringan. Ini adalah cara yang bagus untuk mendeteksi hal-hal seperti lalu lintas C2 , eksfiltrasi data, dan pergerakan lateral. Gambar di bawah menunjukkan contoh output NetFlow . Seperti yang kita lihat, contoh tersebut tidak berisi paket individual tetapi metadata tentang aliran paket yang mengalir dari IP sumber 12.1.1.1 ke IP tujuan 13.1.1.2.
<img width="385" height="486" alt="image" src="https://github.com/user-attachments/assets/74f4d445-2b81-42ab-bb61-bca7f85200fa" />
Protokol Internet Protocol Flow Information Export ( IPFIX ) dapat dianggap sebagai penerus NetFlow . NetFlow awalnya merupakan protokol milik Cisco. Ini berarti bahwa protokol tersebut dirancang hanya untuk sistem Cisco. Baru mulai dari NetFlow v9 Cisco menyertakan templating, sehingga vendor lain dapat mengadaptasinya ke perangkat mereka. Dalam kolaborasi dengan Cisco dan vendor lain, IETF menciptakan IPFIX dan merilisnya sebagai standar netral vendor. IPFIX menawarkan fitur yang mirip dengan NetFlow , tetapi mencakup lebih banyak fleksibilitas dalam mengkonfigurasi bidang mana yang akan ditangkap.

Untuk mengimplementasikan NetFlow atau IPFIX , kita tidak memerlukan infrastruktur baru atau server khusus. Sebagian besar vendor mengimplementasikan protokol ini secara standar di perangkat mereka. Kita hanya perlu mengaktifkan dan mengkonfigurasi protokol serta menyediakan tempat untuk mengirim metadata. Anda tidak memerlukan server khusus untuk mengumpulkan data ini; banyak NGFW, IPS , dan IDS memiliki implementasi untuk mengumpulkan dan menganalisis data aliran.
Kesimpulan
Sekarang kita sudah tahu apa itu NTA , mengapa kita membutuhkannya, bagaimana cara menangkap lalu lintas jaringan dan menganalisisnya; kita siap untuk mulai menganalisis lalu lintas jaringan secara efektif menggunakan alat bernama Wireshark. 




