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
    Interceptor.replace(
        new NativeFunction(Module.findExportByName('advapi32.dll', 'RegGetValueW'), "uint", ["pointer", "pointer", "pointer", "uint32", "pointer", "pointer", "pointer" ]), 
        new NativeCallback((a, b, c, d, e, f, g) => { 
          let str = "23423423423:fff"; // my code checks for length > 8, so i have to create a long dummy string
          let size = str.length * 2 + 2;
          if (f == 0) {
            g.writeU32(size); 
          } else {
            let retPtr = Memory.allocUtf16String(str);
            retPtr.writeUtf16String(str);
            Memory.copy(f, retPtr, size);
            // f.writeUtf16String();  does not work, it seems f needs re-allocation
          }

          return 0; 
        }, "uint", ["pointer", "pointer", "pointer", "uint32", "pointer", "pointer", "pointer" ])
      );
    var aDict = new Array();


var fNtQueryKey = new NativeFunction(
    Module.findExportByName('Ntdll.dll', 'NtQueryKey'),
    "uint",
    [
        "pointer",
        "uint", 
        "pointer", 
        "uint",
        "pointer"
    ]
);


function getKeyPath(hKey)  {
    var pBuff = Memory.alloc(0x1000);
    var pRes = Memory.alloc(0x4);
    var iNTSTATUS = fNtQueryKey(hKey, 3, pBuff, 0x1000, pRes);
    if (iNTSTATUS == 0) { //NTSTATUS_SUCCESS
        return (pBuff.add(4)).readUtf16String();
    } else {
        return;
    }
}

function getHivePreDefKey(hKey) {
    if (hKey == 0x80000000) {
        return "HKEY_CLASSES_ROOT";
    } else if (hKey == 0x80000001) {
        return "HKEY_CURRENT_USER";
    } else if (hKey == 0x80000002) {
        return "HKEY_LOCAL_MACHINE";
    } else if (hKey == 0x80000003) {
        return "HKEY_USERS";
    } else if (hKey == 0x80000004) {
        return "HKEY_PERFORMANCE_DATA";
    } else if (hKey == 0x80000050) {
        return "HKEY_PERFORMANCE_TEXT";
    } else if (hKey == 0x80000060) {
        return "HKEY_PERFORMANCE_NLSTEXT";
    } else if (hKey == 0x80000005) {
        return "HKEY_CURRENT_CONFIG";
    } else if (hKey == 0x80000006) {
        return "HKEY_DYN_DATA";
    } else {
        return;
    }
}

    function findInArrayDict(hKey) {
      for (var i = 0; i < aDict.length; i++) {
          if (aDict[i].hKey == hKey.toString()) {
              return aDict[i];
          }
      }
      return;
  }


/*
        Interceptor.attach(Module.findExportByName('Kernel32.dll', 'RegOpenKeyEx'), {
            onEnter: function (args) {

      
                console.log(`${defLookup}`);
                  
              
                             
            },
            onLeave: function(retval) {
              if (retval.toInt32() == 0) { //ERROR_SUCCESS
                    if (this.bStoreRes) {
                        var oReg = {"path": this.sPath, "hKey": ((this.pHandle).readPointer()).toString()};
                        aDict.push(oReg);
                        //send("I stored a val here..");
                    }
                }
            }
        });

*/






 



          Interceptor.attach(Module.findExportByName('advapi32.dll', 'RegGetValueW'), { 
            onEnter: function (args) {
                // Intercepting function entry
                console.log('RegGetValueW called from:');
                
                const hKey = args[0];

                const sBasePath = getKeyPath(hKey);

                //var defLookup = getHivePreDefKey(hKey.toUInt32());


                const lpSubKey = args[1].readUtf16String();
                const lpValue = args[2].readUtf16String();
                const dwFlags = args[3];
                const pdwType = args[4];
                const pvData = args[5];
                const pcbData = args[6];

                console.log('[RegGetValueW] hKey:', sBasePath, 'lpSubKey:', lpSubKey, 'lpValue:', lpValue, 'dwFlags:', dwFlags, 'pdwType:', pdwType, 'pvData:', pvData, 'pcbData:', pcbData);


            },
            onLeave: function (retval) {
                // Intercepting function exit
            }
        });
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