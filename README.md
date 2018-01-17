```
    __  __           __   _____           
   / / / /___ ______/ /__/ ___/__  _______
  / /_/ / __ `/ ___/ //_/\__ \/ / / / ___/
 / __  / /_/ / /__/ ,<  ___/ / /_/ (__  ) 
/_/ /_/\__,_/\___/_/|_|/____/\__, /____/  
                            /____/        
			Extreme Vulnerable Driver
							Exploits
```

### HackSys Extreme Vulnerable Driver - Windows 10 x64 StackOverflow Exploit with SMEP Bypass

Classic StackOverflow exploit, which exploits a vulnerable function within the HEVD Kernel driver.

# How does this exploit work:

* 64 Bit version of the https://github.com/Cn33liz/HSEVD-StackOverflow exploit
* Works almost the same, but in order to work on Windows 10 x64 we need to Bypass SMEP Kernel protections, which prevents us from jumping to our 64 bit usermode Shellcode.
* In order to Bypass SMEP after controlling rip, we need to execute a SMEP bypass ROP chain on the stack (rsp = rip) which changes the value of the cr4 register and then jumps to our usermode Shellcode.
* After running our x64 token stealing shellcode, we restore some registers, jump back to a SMEP enable ROP chain on the stack and return to IrpDeviceIoCtlHandler+0xe2


Runs on:

```
This exploits has been tested succesfully on Windows 10 x64 v1709 (Version 10.0.16299.192).
``` 

Compile Exploit:

```
This project is written in C and can be compiled within Visual Studio.
```

Load Vulnerable Driver:

```
The HEVD driver can be downloaded from the HackSys Team Github page and loaded with the OSR Driver loader utility.
To run on x64, you need to install the Windows Driver Kit (WDK), Windows SDK and recompile with Visual Studio.
```

