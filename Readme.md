CryptographerApp Simple Software
by Alfian Badrul Isnan - 1806148643

Version : 0.26 BETA
alfian.badrul@ui.ac.id | fianshared@gmail.com | git:alfianisnan10

Aplikasi ini merupakan tugas untuk memenuhi Tugas Tambahan Modul 7 : Secure Information
Praktikum Keamanan Jaringan, Teknik Komputer, Departemen Teknik Elektro
Fakultas Teknik, Universitas Indoensia

Sukabumi, 25 April 2020

Command :
(no command)                     : Default program for testing
[any input] ...                  : Hash for multiple message
--file [file] | -f [file]        : Hash file from defined directory
--version | -v                   : version and about this simple software
--help | -h                      : This help page
--algorithm | -a                 : Hashing with specific algorithm (ex: MD5 | SHA1 | SHA256)
--encrypt | -e                   : Encrypt message/file with RSA
--decrypt | -d                   : Decrypt message/file with RSA
--tofile [file] | -tf [file]                     : Export encrypted.data to root directory
--keypairs | -kp                         : Generate New Keypair (Private & Public) Key

Example (Program will run on JVM)
>> CryptographerApp "Hello World" Password123 -a MD5
>> CryptographerApp -algorithm SHA256 --file "C:\Documents\test.txt"
>> CryptographerApp HelloWorld
>> CryptographerApp --encrypt "This is my secret message"
>> CryptographerApp HelloWorld123 --decrypt --tofile .
>> CryptographerApp -e C:\Documents\secretMessage.txt

---- TEST BATCH ---
CryptographerApp Simple Software

Default Program

(MD5)
7e5ce4f56e24ea9da9ed1f66debb4971 : SecureCommunication
e451c41e893dc84fc722c768b3bc0c9a : Computer_Security

(SHA1)
f8aedd363ce07d850f8b4acdd512bc4754a83f76 : When there’s a will, there's a way.

CryptographerApp Simple Software
Successfull generating public.key and private.key


Original Data : Man is a slow, sloppy, and brilliant thinker; computers are fast, accurate, and stupid.
Exported to : D:\Programming\Crypto\encrypted.data

Original Data : encrypted.data
Decrypted : Man is a slow, sloppy, and brilliant thinker; computers are fast, accurate, and stupid.