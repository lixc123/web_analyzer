/**
 * Windows API Hook脚本
 * 用于Hook Windows网络和加密相关API
 */

// 网络API Hook
function hookNetworkAPIs() {
    console.log("[*] 开始Hook网络API...");

    // Hook WinHTTP API
    try {
        const winhttp = Process.getModuleByName("winhttp.dll");

        // Hook WinHttpSendRequest
        const WinHttpSendRequest = winhttp.getExportByName("WinHttpSendRequest");
        if (WinHttpSendRequest) {
            Interceptor.attach(WinHttpSendRequest, {
                onEnter: function(args) {
                    const hRequest = args[0];
                    const lpszHeaders = args[1];
                    const dwHeadersLength = args[2].toInt32();

                    let headers = "";
                    if (!lpszHeaders.isNull() && dwHeadersLength > 0) {
                        headers = lpszHeaders.readUtf16String(dwHeadersLength);
                    }

                    send({
                        type: "network",
                        api: "WinHttpSendRequest",
                        handle: hRequest.toString(),
                        headers: headers,
                        timestamp: Date.now()
                    });
                },
                onLeave: function(retval) {
                    // 返回值处理
                }
            });
            console.log("[+] WinHttpSendRequest Hook成功");
        }

        // Hook WinHttpReceiveResponse
        const WinHttpReceiveResponse = winhttp.getExportByName("WinHttpReceiveResponse");
        if (WinHttpReceiveResponse) {
            Interceptor.attach(WinHttpReceiveResponse, {
                onEnter: function(args) {
                    this.hRequest = args[0];
                },
                onLeave: function(retval) {
                    send({
                        type: "network",
                        api: "WinHttpReceiveResponse",
                        handle: this.hRequest.toString(),
                        success: retval.toInt32() !== 0,
                        timestamp: Date.now()
                    });
                }
            });
            console.log("[+] WinHttpReceiveResponse Hook成功");
        }

    } catch (e) {
        console.log("[-] WinHTTP Hook失败: " + e.message);
    }

    // Hook WinINet API
    try {
        const wininet = Process.getModuleByName("wininet.dll");

        // Hook InternetOpenW
        const InternetOpenW = wininet.getExportByName("InternetOpenW");
        if (InternetOpenW) {
            Interceptor.attach(InternetOpenW, {
                onEnter: function(args) {
                    const lpszAgent = args[0];
                    const dwAccessType = args[1].toInt32();

                    let agent = "";
                    if (!lpszAgent.isNull()) {
                        agent = lpszAgent.readUtf16String();
                    }

                    send({
                        type: "network",
                        api: "InternetOpenW",
                        userAgent: agent,
                        accessType: dwAccessType,
                        timestamp: Date.now()
                    });
                }
            });
            console.log("[+] InternetOpenW Hook成功");
        }

        // Hook HttpSendRequestW
        const HttpSendRequestW = wininet.getExportByName("HttpSendRequestW");
        if (HttpSendRequestW) {
            Interceptor.attach(HttpSendRequestW, {
                onEnter: function(args) {
                    const hRequest = args[0];
                    const lpszHeaders = args[1];
                    const dwHeadersLength = args[2].toInt32();
                    const lpOptional = args[3];
                    const dwOptionalLength = args[4].toInt32();

                    let headers = "";
                    if (!lpszHeaders.isNull() && dwHeadersLength > 0) {
                        headers = lpszHeaders.readUtf16String();
                    }

                    let body = "";
                    if (!lpOptional.isNull() && dwOptionalLength > 0) {
                        try {
                            body = lpOptional.readUtf8String(dwOptionalLength);
                        } catch (e) {
                            body = "<binary data>";
                        }
                    }

                    send({
                        type: "network",
                        api: "HttpSendRequestW",
                        handle: hRequest.toString(),
                        headers: headers,
                        body: body,
                        timestamp: Date.now()
                    });
                }
            });
            console.log("[+] HttpSendRequestW Hook成功");
        }

    } catch (e) {
        console.log("[-] WinINet Hook失败: " + e.message);
    }

    // Hook Socket API
    try {
        const ws2_32 = Process.getModuleByName("ws2_32.dll");

        // Hook send
        const send_func = ws2_32.getExportByName("send");
        if (send_func) {
            Interceptor.attach(send_func, {
                onEnter: function(args) {
                    const socket = args[0].toInt32();
                    const buf = args[1];
                    const len = args[2].toInt32();

                    let data = "";
                    if (!buf.isNull() && len > 0 && len < 4096) {
                        try {
                            data = buf.readUtf8String(len);
                        } catch (e) {
                            data = "<binary data>";
                        }
                    }

                    send({
                        type: "network",
                        api: "send",
                        socket: socket,
                        data: data,
                        length: len,
                        timestamp: Date.now()
                    });
                }
            });
            console.log("[+] send Hook成功");
        }

        // Hook recv
        const recv_func = ws2_32.getExportByName("recv");
        if (recv_func) {
            Interceptor.attach(recv_func, {
                onEnter: function(args) {
                    this.socket = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function(retval) {
                    const bytesReceived = retval.toInt32();
                    if (bytesReceived > 0) {
                        let data = "";
                        try {
                            data = this.buf.readUtf8String(bytesReceived);
                        } catch (e) {
                            data = "<binary data>";
                        }

                        send({
                            type: "network",
                            api: "recv",
                            socket: this.socket,
                            data: data,
                            length: bytesReceived,
                            timestamp: Date.now()
                        });
                    }
                }
            });
            console.log("[+] recv Hook成功");
        }

    } catch (e) {
        console.log("[-] Socket Hook失败: " + e.message);
    }
}

// 加密API Hook
function hookCryptoAPIs() {
    console.log("[*] 开始Hook加密API...");

    try {
        const advapi32 = Process.getModuleByName("advapi32.dll");

        // Hook CryptEncrypt
        const CryptEncrypt = advapi32.getExportByName("CryptEncrypt");
        if (CryptEncrypt) {
            Interceptor.attach(CryptEncrypt, {
                onEnter: function(args) {
                    const hKey = args[0];
                    const hHash = args[1];
                    const Final = args[2].toInt32();
                    const dwFlags = args[3].toInt32();
                    const pbData = args[4];
                    const pdwDataLen = args[5];

                    let dataLen = 0;
                    if (!pdwDataLen.isNull()) {
                        dataLen = pdwDataLen.readU32();
                    }

                    let data = "";
                    if (!pbData.isNull() && dataLen > 0 && dataLen < 4096) {
                        try {
                            data = pbData.readUtf8String(dataLen);
                        } catch (e) {
                            data = "<binary data>";
                        }
                    }

                    send({
                        type: "crypto",
                        api: "CryptEncrypt",
                        keyHandle: hKey.toString(),
                        data: data,
                        dataLength: dataLen,
                        timestamp: Date.now()
                    });
                }
            });
            console.log("[+] CryptEncrypt Hook成功");
        }

        // Hook CryptDecrypt
        const CryptDecrypt = advapi32.getExportByName("CryptDecrypt");
        if (CryptDecrypt) {
            Interceptor.attach(CryptDecrypt, {
                onEnter: function(args) {
                    const hKey = args[0];
                    const hHash = args[1];
                    const Final = args[2].toInt32();
                    const dwFlags = args[3].toInt32();
                    const pbData = args[4];
                    const pdwDataLen = args[5];

                    this.pbData = pbData;
                    this.pdwDataLen = pdwDataLen;
                    this.hKey = hKey;
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        let dataLen = 0;
                        if (!this.pdwDataLen.isNull()) {
                            dataLen = this.pdwDataLen.readU32();
                        }

                        let data = "";
                        if (!this.pbData.isNull() && dataLen > 0 && dataLen < 4096) {
                            try {
                                data = this.pbData.readUtf8String(dataLen);
                            } catch (e) {
                                data = "<binary data>";
                            }
                        }

                        send({
                            type: "crypto",
                            api: "CryptDecrypt",
                            keyHandle: this.hKey.toString(),
                            data: data,
                            dataLength: dataLen,
                            timestamp: Date.now()
                        });
                    }
                }
            });
            console.log("[+] CryptDecrypt Hook成功");
        }

    } catch (e) {
        console.log("[-] Crypto Hook失败: " + e.message);
    }
}

// 主函数
function main() {
    console.log("[*] Windows API Hook脚本已加载");
    console.log("[*] 进程: " + Process.id + " - " + Process.getCurrentThreadId());

    // Hook网络API
    hookNetworkAPIs();

    // Hook加密API
    hookCryptoAPIs();

    console.log("[*] Hook完成，开始监控...");
}

// 执行主函数
main();
