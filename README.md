# REhelper
This tool is designed to help with doing reverse engineering tasks. <br />
For example this program comes with tools that will help you do the job. <br />

[![REhelper](https://github.com/3XPL017/REhelper/blob/master/images/usage.png)

__Debug options__
This tool can be used at a target to help you test your own reversing tools this can be done by using the debug options. For example if you are creating a disassembler you can use --address to make sure that your disassembler is correctly resolving the address of functions. Or you can use --ptrace if you are not sure if your application will get detected by it. You can use --break if your are building a debugger to make sure that it handles break points correctly. Of course these are just examples of what you can do with them.<br />

## Compile
__gcc REhelper.c -o REhelper -lcrypto__ <br />
