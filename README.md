# OneTimeEncryptor

A small application using ECDH([Elliptic curve Diffie–Hellman](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman)) for file encryption.

## Usage

Before using it to encrypt/decrypt file, you need to click `Key`->`Generate key` to generate a key pair. Then you'll be asked to input password. The password is used to encrypt private key.

Public key is used to encrypt file while private key is used to decrypt file.

You can encrypt any file without entering password using public key. But once want to decrypt any file, you need to enter password to decrypt private key firstly.

### Command line option

```OneTimeEnc [enc|dec] file1 file2 file3...```

`enc` means start application for "encryption", then automatically encrypt file1, file2, file3...

`dec` means  start application for "decryption", then automatically decrypt file1, file2, file3...



## Build

### Requirements

G++4.7, Visual Studio 2012 or higher, Visual Studio 2015 update 3 tested

Qt5.0 or higher, Qt 5.9 MSVC2015 32bit tested

OpenSSL v1.1.0 or higher, [Win32 OpenSSL v1.1.0f](https://slproweb.com/download/Win32OpenSSL-1_1_0f.exe) tested

### Step

1. Clone this repo
2. Open `OneTimeEncryptor.pro` with QtCreator
3. Modifiy `INCLUDEPATH +=` and  `LIBS +=` to where OpenSSL actually locates
4. Build & Run