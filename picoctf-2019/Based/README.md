## 問題文

```
To get truly 1337, you must understand different data encodings, such as hexadecimal or binary. Can you get the flag from this program to prove you are on the way to becoming 1337? Connect with nc 2019shell1.picoctf.com 20836.
```



2進数や8進数、16進数が与えられるのでそれを文字列に直して、与えるとフラグが得られる

brewが壊れていて、直したらpwntoolsが消えていたのでもう一回導入した。

一応、参考までに(python3,macでの環境の場合)

```
brew install python
brew install pwntools
pip3 install pwntools 
```

そして今回書いたコードがこちら

```python
from pwn import *
import re
import string
import binascii

#context.log_level = "DEBUG"
def unknown_base(l_sp):
    for base in range(1,17):
        flag = True
        res = ""
        try:
            for t in l_sp:
                c = chr(int(t,base))
                if c not in string.ascii_letters:
                    flag = False
                    break
                res += c
            if(flag):
                log.info("decode successful with base{} res = {}".format(base,res))
                return res
        except:
            pass
        
r = remote("2019shell1.picoctf.com", 20836)

print(r.recvuntil("give the "))
l = r.recvuntil(" as")
l_sp = l[:-2].split()
print(l_sp)

ans = ""
ans = unknown_base(l_sp)

print(ans)
r.sendlineafter("Input:",ans)
print(r.recvuntil("give me the "))
l = r.recvuntil(" as")
l_sp = l[:-2].split()
print(l_sp)
ans = ""
ans = unknown_base(l_sp)
print(ans)
r.sendlineafter("Input:",ans)
r.recvuntil(b'give me the ')
l = r.recvuntil(" as")
print(l)
ans = binascii.a2b_hex(l[:-3])
print(ans)

r.sendlineafter("Input:",ans)
print(r.recvall())
r.close()
```



ネットにのっているコードがpython2系だったり、今は推奨されていない関数が使われていたので苦労した



