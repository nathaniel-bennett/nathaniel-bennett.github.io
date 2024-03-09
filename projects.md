---
layout: framework
title: Projects
banner: "/assets/images/banners/code-blurred-banner-short2.jpeg"
---

<!-- TODO: add libSPF2 CVEs here -->

# WinSharpFuzz (libFuzzer Adaption for Windows .NET)

As part of an internship with ManTech, I had the opportunity to explore various 
Red team techniques. A little way into the project, I came to discover that fuzzing 
frameworks for C# code are nearly nonexistent. Traditional fuzzing options such as 
WinAFL quickly led to complications due to the way that .NET uses JIT compilation. 
One framework turned out to be a viable solution ([SharpFuzz](https://github.com/metalnem/sharpfuzz)), 
but its support was limited to .NET Core code (a platform-independant subset of .NET) 
and only ran on Linux.

So, after expending all possible alternatives, I determined to port over SharpFuzz to 
introduce compatibility with Windows. This mostly involved introducing Windows equivalents 
of `pipe(3)`, `mmap`/`shmat` and other system calls, as well as refactoring the C# harness 
framework to be compatible with these modifications. In the end, my intern team was able to 
get the new fuzzer port (dubbed WinSharpFuzz) up and running, and it became a great asset 
in searching for program crashes. ManTech was very accomadating with the project, and they 
granted a request to make WinSharpFuzz an open-source tool :).

Like SharpFuzz, the WinSharpFuzz framework can be used to find undesired exceptions in library 
functions. In addition, it adds support for mixed-mode .NET assemblies, so it can fuzz any 
libraries that call native or unsafe code (calls to `Marshal` or `unsafe` functions, for instance). 
These features make it uniquely capable of fuzzing all kinds of Windows .dll assemblies.

```cs
using System;
using SharpFuzz;

namespace TestExample1
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Fuzzer.LibFuzzer.Run(bytes =>
            {
                try
                {
                    // pass input bytes to library method(s) here
                }
                catch (ExampleException)
                {
                    // Catch exceptions that would normally be thrown from methods
                }

                // Uncaught exceptions and full-blown crashes will be reported
            });
        }
    }
}
```

Find the project here: [github.com/nathaniel-bennett/winsharpfuzz](https://github.com/nathaniel-bennett/winsharpfuzz)

# Sender Policy Framework (SPF) Research

As part of researching the ins and outs of the Sender Policy Framework, I experimented 
with various implementations to look for any inconsistent behavior. The results of this 
research are forthcoming in a few papers. I'll write up more about this once the 
disclosure and remediation process is complete.

# SecureDNS

Toward the end of my time working in the Usable Security & Privacy Lab, I began 
tinkering around with using macros in C as a means of transparently adding 
functionality into core system functions. The C programming language allows 
function macros to have the same name as a regular function; the result of doing 
this is that every instance of that function is replaced at compile time with whatever 
is defined by the macro. My end goal was to accomplish something similar to the 
Secure Socket API--where additional functionality (TLS) was added to the sockets 
API via extra function options--but without the hassle of loading a kernel module.

With this in mind, I implemented a library that adds DNS over TLS to the `getaddrinfo` 
function, a commonly-used interface for DNS lookups. I also added support for poll-based 
nonblocking DNS lookups, a feature desperately needed in C.

The end product is a very minimal addition to the existing API:

```c
#include <netdb.h> /* Note that netdb can be included--it won't break anything */
#include <securedns.h> /* <-- library included */

int main(int argc, char *argv[]) {
   struct addrinfo *result;

   struct addrinfo hints = {
       .ai_family = AF_INET6,
       .ai_socktype = SOCK_STREAM,
       .ai_flags = AI_NUMERICSERV | AI_TLS, /* <-- `AI_TLS` added to hints */
   };

   int ret = getaddrinfo("nathanielbennett.com", "443", &hints, &result); 
   /* ^ no change needed for the function call; runs DNS over TLS transparently */
   if (ret != 0)
       exit(1);
   
   /* create socket here, connect to host, and so on */

   return 0;
}
```

The only changes to the API are the additions of the `AI_TLS` and `AI_NONBLOCKING` 
flags, which can be easily added in the `ai_flags` field. An existing project could 
trivially switch over their entire codebase to DNS over TLS by adding this library and 
inserting a single flag into the appropriate field.

Learn more about it here: [https://github.com/nathaniel-bennett/securedns](https://github.com/nathaniel-bennett/securedns)


# Secure Socket API Research

The Secure Socket API (SSA) maps the various complex functions of Transport Layer Security (TLS) to the POSIX Sockets API. It does so by using a kernel module (which adds the 
IPPROTO_TLS protocol to the TCP protocol stack) and a network daemon (which keeps track 
of TLS state and performs transparent encryption/decryption).

Most of my work was focused on refining and adding functionality to the proof of concept 
that had been created. While the prototype supported basic TLS operations (hostname 
validation, some certificate loading and connection-based functions), there were more 
complex aspects of TLS that needed to be added:

* Session caching and resumption
* Certificate revocation checks (OCSP, CRL and OCSP stapling)
* Certificate transparency validation
* Various other aspects to certificate validation

I'd have to say my favorite feature to add was certificate revocation--I worked with it 
until I was able to have all revocation mechanisms working simultaneously (multiple 
OCSP/CRL queries), with the first authoritative answer being accepted. This boosted the 
speed of connection negotiation, especially in cases where some of the revocation 
sources were slow to connect or even unreachable. Server-side OCSP stapling was also a 
fun challenge.

I also worked quite a bit on the kernel side of the SSA. In particular, I added IPv6/TCP stack support, ported the existing implementation to the most recent Linux kernel version (the Netlink API had changed), and made a few tweaks to ensure that failure states were always properly accounted for.

Learn more about the Secure Socket API here: [https://owntrust.org/ssa](https://owntrust.org/ssa)

- userspace daemon: [github.com/Usable-Security-and-Privacy-Lab/ssa-daemon](https://github.com/Usable-Security-and-Privacy-Lab/ssa-daemon)
- kernel module: [github.com/Usable-Security-and-Privacy-Lab/ssa](https://github.com/Usable-Security-and-Privacy-Lab/ssa)
