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