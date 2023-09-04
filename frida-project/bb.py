# from __future__ import print_function
# import frida
# import sys

# def on_message(message, data):
#     print("[%s] => %s" % (message, data))

# def main(target_process):
#     session = frida.attach(target_process)

#     script = session.create_script("""

#     // Find base address of current imported jvm.dll by main process fledge.exe
#     var baseAddr = Module.findBaseAddress('Jvm.dll');
#     console.log('Jvm.dll baseAddr: ' + baseAddr);

#     var SetAesDeCrypt0 = resolveAddress('0x1FF44870'); // Here we use the function address as seen in our disassembler

#     Interceptor.attach(SetAesDeCrypt0, { // Intercept calls to our SetAesDecrypt function

#         // When function is called, print out its parameters
#         onEnter: function (args) {
#             console.log('');
#             console.log('[+] Called SetAesDeCrypt0' + SetAesDeCrypt0);
#             console.log('[+] Ctx: ' + args[0]);
#             console.log('[+] Input: ' + args[1]); // Plaintext
#             console.log('[+] Output: ' + args[2]); // This pointer will store the de/encrypted data
#             console.log('[+] Len: ' + args[3]); // Length of data to en/decrypt
#             dumpAddr('Input', args[1], args[3].toInt32());
#             this.outptr = args[2]; // Store arg2 and arg3 in order to see when we leave the function
#             this.outsize = args[3].toInt32();
#         },

#         // When function is finished
#         onLeave: function (retval) {
#             dumpAddr('Output', this.outptr, this.outsize); // Print out data array, which will contain de/encrypted data as output
#             console.log('[+] Returned from SetAesDeCrypt0: ' + retval);
#         }
#     });

#     function dumpAddr(info, addr, size) {
#         if (addr.isNull())
#             return;

#         console.log('Data dump ' + info + ' :');
#         var buf = addr.readByteArray(size);

#         // If you want color magic, set ansi to true
#         console.log(hexdump(buf, { offset: 0, length: size, header: true, ansi: false }));
#     }

#     function resolveAddress(addr) {
#         var idaBase = ptr('0x1FEE0000'); // Enter the base address of jvm.dll as seen in your favorite disassembler (here IDA)
#         var offset = ptr(addr).sub(idaBase); // Calculate offset in memory from base address in IDA database
#         var result = baseAddr.add(offset); // Add current memory base address to offset of function to monitor
#         console.log('[+] New addr=' + result); // Write location of function in memory to console
#         return result;
#     }
# """)
#     script.on('message', on_message)
#     script.load()
#     print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
#     sys.stdin.read()
#     session.detach()

# if __name__ == '__main__':
#     if len(sys.argv) != 2:
#         print("Usage: %s <process name or PID>" % __file__)
#         sys.exit(1)

#     try:
#         target_process = int(sys.argv[1])
#     except ValueError:
#         target_process = sys.argv[1]
#     main(target_process)

from __future__ import print_function
import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script("""
      Interceptor.attach(Module.findExportByName('advapi32.dll', 'RegGetValueW'), { 
            onEnter: function (args) {
                // Intercepting function entry
                console.log('RegGetValueW called from:');
                
                const hKey = args[0];
                const lpSubKey = args[1].readUtf16String();
                const lpValue = args[2].readUtf16String();
                const dwFlags = args[3];
                const pdwType = args[4];
                const pvData = args[5];
                const pcbData = args[6];

                console.log('[RegGetValueW] hKey:', hKey, 'lpSubKey:', lpSubKey, 'lpValue:', lpValue, 'dwFlags:', dwFlags, 'pdwType:', pdwType, 'pvData:', pvData, 'pcbData:', pcbData);

                // // Get the original function pointer
                const originalRegGetValueW = new NativeFunction(Module.findExportByName('advapi32.dll', 'RegGetValueW'), 
                'uint', 
                ['pointer', 
                'pointer', 
                'pointer', 
                'uint', 
                'pointer', 
                'pointer', 
                'pointer'
                ]);

                console.log('[RegGetValueW] pointer is truey ?:', !!originalRegGetValueW);
                
                // Call the original function
                // TODO: fix this
                const returnValue = originalRegGetValueW(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);

                // Intercepting the return value
                console.log('[RegGetValueW] Return Value:', returnValue);
            },
            onLeave: function (retval) {
                // Intercepting function exit
            }
        });

/*
      Interceptor.attach(RegOpenKeyExA, {
        onEnter: function (args) {
          const hKey = args[0];
          const lpSubKey = args[1].readUtf8String();
          const samDesired = args[2];

          console.log('[RegOpenKeyExA] hKey:', hKey, 'lpSubKey:', lpSubKey, 'samDesired:', samDesired);
        },
        onLeave: function (retval) {}
      });

      Interceptor.attach(RegQueryValueExW, {
        onEnter: function (args) {
          const hKey = args[0];
          const lpValueName = args[1].readUtf16String();

          console.log('[RegQueryValueExW] hKey:', hKey, 'lpValueName:', lpValueName);
        },
        onLeave: function (retval) {}
      });

      Interceptor.attach(RegQueryValueExA, {
        onEnter: function (args) {
          const hKey = args[0];
          const lpValueName = args[1].readUtf8String();

          console.log('[RegQueryValueExA] hKey:', hKey, 'lpValueName:', lpValueName);
        },
        onLeave: function (retval) {}
      });

      Interceptor.attach(RegCloseKey, {
        onEnter: function (args) {
          const hKey = args[0];

          console.log('[RegCloseKey] hKey:', hKey);
        },
        onLeave: function (retval) {}
      });

      Interceptor.attach(RegCloseKeyA, {
        onEnter: function (args) {
          const hKey = args[0];

          console.log('[RegCloseKeyA] hKey:', hKey);
        },
        onLeave: function (retval) {}
      });*/
""")
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)