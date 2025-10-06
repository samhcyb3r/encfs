1.	Writing a New System Call and Integrating it into Linux Kernel
•	Students are asked to write a new system call named sys_hello, which will return a simple string such as "Hello, World!" to the user. (20 pts)

Code Example (for sys_hello):
```
// sys_hello.c file in the kernel source tree

#include <linux/kernel.h> #include <linux/syscalls.h>

SYSCALL_DEFINE0(hello) {
printk(KERN_INFO "Hello, World! system call invoked.\n"); return 0;
}
```


