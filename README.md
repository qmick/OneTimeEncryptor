# OneTimeEncryptor
[![Build Status](https://travis-ci.org/qmick/OneTimeEncryptor.svg?branch=master)](https://travis-ci.org/qmick/OneTimeEncryptor)

一个利用公钥加密来做文件加密的小程序，一次产生密钥，此后加密无需密码，支持重设密码

## 使用

在进行加密前，要先点击`Key`->`Generate key`来产生密钥对。然后会要求你输入密码来加密私钥。

**警告**：产生密钥对的操作会**覆盖掉**之前产生的密钥对，请务必确保没有文件是用之前产生的密钥加密的，不然你将永远无法解密这些文件

公钥是用来加密文件，而私钥用来解密文件。在加密文件的时候不需要输入密码，只有在解密文件时，才需要输入密码解密私钥以解密文件。

### 命令行选项

```OneTimeEncryptor [enc|dec] file1 file2 file3...```

`enc` 参数是指以加密模式打开程序，在该模式下只会加载公钥，自动加密file1 file2 file3...，然后自动退出。

`dec` 参数是指以解密模式打开程序，在该模式下只会加载私钥，自动解密file1 file2 file3...，然后自动退出。


## 编译
### 环境要求
编译器: G++4.9或更高。G++4.9.4 和 Visual Studio 2015 update 3 已经过测试

Qt版本: Qt 5.0或更高。Qt 5.2.1 Linux 和 Qt 5.9 MSVC2015 32bit 已经过测试

Botan版本:Botan-2或更高。Botan-2.1.0已经过测试

### 步骤
1. `git clone `
2. 打开 `OneTimeEncryptor.pro`
3. 修改 `INCLUDEPATH +=` 和  `LIBS +=` 到Botan的实际位置
4. qmake && make 或者用QtCreator打开项目编译

# OneTimeEncryptor

A small application using ECDH([Elliptic curve Diffie–Hellman](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman)) for file encryption. Once key pair generated, encryption need no password and support password reset.

## Usage

Before using it to encrypt/decrypt file, you need to click `Key`->`Generate key` to generate a key pair. Then you'll be asked to input password. The password is used to encrypt private key.


**Warning**: `Generate key` will **overwrite** the previous key. make sure no file is encrypted with the previous key otherwise you'll lose your data forever.

Public key is used to encrypt file while private key is used to decrypt file.

You can encrypt any file without entering password using public key. But once want to decrypt any file, you need to enter password to decrypt private key firstly.

### Command line option

```OneTimeEncryptor [enc|dec] file1 file2 file3...```

`enc` means start application for "encryption", load public key only, automatically encrypt file1, file2, file3... then exit.

`dec` means start application for "decryption", load private key only, automatically decrypt file1, file2, file3... then exit.



## Build

### Requirements

Compiler: G++4.9 or higher. G++4.9.4 and Visual Studio 2015 update 3 are tested

Qt: Qt 5.0 or higher. Qt 5.2.1 Linux and Qt 5.9 MSVC2015 32bit are tested

Botan: Botan-2 or higher. Botan-2.1.0 tested

### Step

1. Clone this repo
2. Open `OneTimeEncryptor.pro` with QtCreator
3. Modifiy `INCLUDEPATH +=` and  `LIBS +=` to where Botan actually locates
4. qmake && make or use QtCreator open this project and compile
