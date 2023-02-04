---
title: Patching Steam binaries
slug: patching-steam-binaries
type:
  - post
  - posts
date: 2023-02-04
---

Patching Steam executable files can prove useful for diverse purposes, one of those being vulnerability research in the Steam client. This short post will explain how you can circumvent a few obstacles to achieve that, before presenting an applied example.

<!--more-->

---

If you're trying to modify a binary from the Steam client, you will most likely end up facing one or both of the following problems:

* Steam tends to **pull updates** when local files are not up-to-date;
* there is an additional **integrity check** for certain executables in the Steam folder.

The first problem is easy to address: by creating a file named `Steam.cfg` at the root of your Steam folder that contains the following setting,
you can prevent Steam from pulling updates automatically.

```
BootStrapperInhibitAll=Enable
```

Regardless, preventing automatic updates is always a crucial point when you're reverse engineering a product &mdash; several times I have had to start working on new IDA bases all over again because binaries got carelessly replaced.

As for the integrity check, we need to find where it comes from. Let's say we wanted to modify the `steamerrorreporter.exe` file: we can assume that at some point, there is a certain component in Steam that opened this file for reading in order to assess whether it was tampered with or not.

A quick use of [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) to find which process opened the `steamerrorreporter.exe` file for reading points towards `steam.exe`, and more especially the following module: `SteamUI.dll`. This DLL is responsible for all kinds of logic in the Steam client (including some funny stuff that you wouldn't necessarily think lies inside a DLL with "UI" in its name, stay tuned for more).

Climbing up the call stack and exploring around a bit, we end up in a function that starts like the following:

```cpp
bool __cdecl sub_6F6B80(int a1, int a2, int a3, int a4, int a5) {

  if ( g_VProfProfilesRunningCount ) {
    v6 = VProfInternalEnterScopeCurrentThread("CCrypto::RSAVerifySignature");
  }

  // ...
```

We understand the purpose of this function is to verify whether a given RSA signature is valid from an input buffer and a public key. It is merely a wrapper around the OpenSSL library.

> *This is, by the way, a typical example of a function leaking its name because of profiling logic: very convenient when you're having a hard time reversing a huge binary without any debug symbol. Coming up with a small IDA script to automatically rename these kinds of functions (there are a lot in Steam and other Valve related products) is an appropriate strategy.*

There is only one cross-reference to this `CCrypto::RSAVerifySignature` method: a function that I will call `VerifyPEIntegrity`.

It starts off with a few sanity checks to ensure it's dealing with a PE binary:

```cpp
if ( Size < 0x200 )
  return ERR;
if ( *(_WORD *)FileContents != 'ZM' )
  return ERR;
v4 = *((_DWORD *)FileContents + 15);
if ( v4 < 0x40 || v4 >= Size - 248 || *(_DWORD *)&FileContents[v4] != 'EP' )
  return ERR;
```

Then, it looks for the string "VLV" at a specific place:

```cpp
if ( *((_DWORD *)FileContents + 16) != 'VLV' )
  return ERR;
if ( *((_DWORD *)FileContents + 17) != 1 )
  return ERR;
```

Something related to Valve? What could it mean? Let's check it out inside an actual binary from the Steam folder:

<pre style="background:rgba(20,20,40,0.9)">
<span style="color:#fff">╭─</span><b><span style="color:#67F86F">face@0xff</span></b><span style="color:#fff"> </span><b><span style="color:#6A76FB">~/Steam </span></b><span style="color:#fff"></span>
<span style="color:#fff">╰─</span><b><span style="color:#fff">$</span></b><span style="color:#fff"> hexdump -C steamerrorreporter.exe | head -n 20</span>
<span style="color:#fff">00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|</span>
<span style="color:#fff">00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|</span>
<span style="color:#fff">00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|</span>
<span style="color:#fff">00000030  00 00 00 00 00 00 00 00  00 00 00 00 10 01 00 00  |................|</span>
<span style="color:#fff">00000040  </span><span style="color:#8f0">56 4c 56 00</span> <span style="color:#8ff">01 00 00 00</span>  <span style="color:#f08">00 94 08 00</span> <span style="color:#f8f">0b ab c0 63</span>  <span style="color:#fff">|</span><span style="color:#8f0">VLV.</span><span style="color:#8ff">....</span><span style="color:#f08">....</span><span style="color:#f8f">...c</span><span style="color:#fff">|</span>
<span style="color:#ff8">00000050  9c ba 32 41 f5 6d 22 8c  89 b3 65 89 56 71 82 2b  |..2A.m"...e.Vq.+|</span>
<span style="color:#ff8">00000060  e3 9f 76 d2 8e c9 06 53  cb 07 ae 53 15 4c 57 7a  |..v....S...S.LWz|</span>
<span style="color:#ff8">00000070  58 c3 f7 84 69 16 43 6d  7a 1b b0 fb 30 48 75 d1  |X...i.Cmz...0Hu.|</span>
<span style="color:#ff8">00000080  67 fc 7c f8 87 30 5d 26  8e 78 58 a0 ed 70 3a d8  |g.|..0]&.xX..p:.|</span>
<span style="color:#ff8">00000090  c3 a5 b0 0f ca ae 11 61  9d 80 29 ff 13 eb e6 9a  |.......a..).....|</span>
<span style="color:#ff8">000000a0  f9 4a b8 fa d9 b3 cb b2  78 b0 ea da 09 a1 88 14  |.J......x.......|</span>
<span style="color:#ff8">000000b0  05 65 98 68 90 0b a3 f9  42 b1 a3 24 ca 37 24 f4  |.e.h....B..$.7$.|</span>
<span style="color:#ff8">000000c0  6f df 36 c5 a9 3d 14 19  47 d9 39 73 16 e8 9f e9  |o.6..=..G.9s....|</span>
<span style="color:#fff">000000d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|</span>
<span style="color:#fff">*                                                                             </span>
<span style="color:#fff">00000110  50 45 00 00 4c 01 05 00  09 ab c0 63 00 00 00 00  |PE..L......c....|</span>
<span style="color:#fff">00000120  00 00 00 00 e0 00 02 01  0b 01 0e 1d 00 d6 02 00  |................|</span>
<span style="color:#fff">00000130  00 ba 05 00 00 00 00 00  e6 9c 00 00 00 10 00 00  |................|</span>
<span style="color:#fff">00000140  00 f0 02 00 00 00 40 00  00 10 00 00 00 02 00 00  |......@.........|</span>
<span style="color:#fff">00000150  06 00 00 00 00 00 00 00  06 00 00 00 00 00 00 00  |................|</span>
</pre>

There is a custom block of data sitting between the DOS header and the NT header, in place of the usual DOS stub. It is composed of a <span style="text-decoration:underline;text-decoration-color:#8f0">magic number</span> (VLV), a <span style="text-decoration:underline;text-decoration-color:#8ff">version number</span> (1), a <span style="text-decoration:underline;text-decoration-color:#f08">signed data size</span>, a <span style="text-decoration:underline;text-decoration-color:#f8f">timestamp</span>, and a <span style="text-decoration:underline;text-decoration-color:#ff8">128-byte signature</span>.

Later on, this <span style="text-decoration:underline;text-decoration-color:#ff8">128-byte signature</span> (highlighted in yellow) is extracted from this header, and null bytes are put in place of the extracted data:

```cpp
qmemcpy(sig, FileContents + 0x50, 0x80);
memset_(FileContents + 0x50, 0, 0x80);
```

Eventually, the function loops through a list of **Valve public keys**:

```cpp
SignatureOK = 0;
k = 0;
do {
  if (k >= nPublicKeys)
    break;
  SignedDataSize = *(_DWORD *)(FileContents + 0x48);
  a5[1] = 1;
  a5[2] = 0;
  a5[3] = 0;
  a5[0] = (int)&off_949C90;
  if (sub_6F6730(a5, PublicKeys[k]) && sub_6F6480(a5))
    SignatureOK = CCrypto::RSAVerifySignature(FileContents, SignedDataSize, sig, 128, a5);
  else
    SignatureOK = 0;
  sub_6F6390(a5);
  ++k;
}
while (!SignatureOK);
```

We understand that the 128-byte signature is an **embedded RSA signature** for the whole file. If the signature is verified against at least one of Valve's public keys, then the file is deemed authentic.

Of course, this whole verification can be easily circumvented by patching this function itself, so that it always returns 0 (valid). In order to achieve that, we can replace the `setz al` (`0F 94 C0`) in the epilog by a `xor eax, eax ; nop` (`31 C0 90`).

```
VerifyPEIntegrity+20F     setz    al          ; <-- patch
VerifyPEIntegrity+212     pop     esi
VerifyPEIntegrity+213     mov     esp, ebp
VerifyPEIntegrity+215     pop     ebp
VerifyPEIntegrity+216     retn
```

Voilà, nothing can stop us from tampering with Steam binaries now!


## Application: patching the Steam Error Reporter

Here is an example use case where patching a Steam binary can come in handy during vulnerability research.

Whenever the Steam client crashes, it usually generates a crash dump for free, which is saved to a folder named `dumps`. These can be analyzed post-mortem, and used to report bugs to Valve.

However, these dumps are quite small by default (a few hundreds of kilobytes), and it is sometimes convenient to have the full crash dumps for deeper analysis. One can achieve that through patching the *Steam Error Reporter* component.

Indeed, crash events are sent over to the `steamerrorreporter.exe` process, which uses the function [`MiniDumpWriteDump`](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) from the Win32 API in order to generate crash dumps.

This function is not imported directly: it is rather retrieved through a [`GetProcAddress`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) call. The code that eventually calls `MiniDumpWriteDump` can thus be identified by searching for references to the string `"MiniDumpWriteDump"`.

```cpp
FARPROC __thiscall GetMiniDumpWriteDump(CTX *this) {
  // ...

  if (!this->pMiniDumpWriteDump) {
    if (!this->DbghelpModule)
      this->DbghelpModule = LoadLibraryW(L"dbghelp.dll");
    if (this->DbghelpModule)
      this->pMiniDumpWriteDump = GetProcAddress(this->DbghelpModule, "MiniDumpWriteDump");
  }

  return this->pMiniDumpWriteDump;
}
```

Then later, in the parent function:

```cpp
FARPROC pMiniDumpWriteDump = GetMiniDumpWriteDump((CTX *)this);

if (pMiniDumpWriteDump) {

  /* ... */

  pMiniDumpWriteDump(
    *(_DWORD *)(this + 16),
    *(_DWORD *)(this + 20),
    *(_DWORD *)(this + 131404),
    *(_DWORD *)(this + 40) | 4,
    v22,
    v27,
    0
  );

}
```

According to the Microsoft specification, the fourth argument is the [`DumpType`](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_type) information. We should set the `0x2` bit to enable the `MiniDumpWithFullMemory` flag; in other words, replace the `or eax, 4` instruction (`83 C8 04`) with `or eax, 2` (`83 C8 02`).

```
.text:00402E45     push    eax
.text:00402E46     mov     eax, [edi+28h]
.text:00402E49     or      eax, 4                   ;  <-- patch
.text:00402E4C     push    eax
.text:00402E4D     push    dword ptr [edi+2014Ch]
.text:00402E53     push    dword ptr [edi+14h]
.text:00402E56     push    dword ptr [edi+10h]
.text:00402E59     call    ebp
```

Steam is now able to generate full-fledged crash dumps with hundreds of megabytes!
