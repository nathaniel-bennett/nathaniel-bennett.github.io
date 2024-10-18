#



```c
pcap_read_bpf(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_bpf *pb = p->priv;
	ssize_t cc;
	int n = 0;
	register u_char *bp, *ep;
	u_char *datap;

    cc = p->cc;

    // Some code that determines which buffer `bp` is assigned here...
    bp = p->bp;
	ep = bp + cc;

	while (bp < ep) {
		register u_int caplen, hdrlen;

        // Some conditional breakout code here...

		caplen = bhp->bh_caplen;
		hdrlen = bhp->bh_hdrlen;
		datap = bp + hdrlen;

        if (packet_passes_bpf_filter) {
            // Some timestamp processing here...

            bp += BPF_WORDALIGN(caplen + hdrlen);
			if (++n >= cnt && !PACKET_COUNT_IS_UNLIMITED(cnt)) {
				p->bp = bp;
				p->cc = (int)(ep - bp);
				/*
                 * ep is set based on the return value of read(),
                 * but read() from a BPF device doesn't necessarily
                 * return a value that's a multiple of the alignment
                 * value for BPF_WORDALIGN().  However, whenever we
                 * increment bp, we round up the increment value by
                 * a value rounded up by BPF_WORDALIGN(), so we
                 * could increment bp past ep after processing the
                 * last packet in the buffer.
                 *
                 * We treat ep < bp as an indication that this
                 * happened, and just set p->cc to 0.
                 */
				if (p->cc < 0)
					p->cc = 0;
				return (n);
			}
        } else {
            bp += BPF_WORDALIGN(caplen + hdrlen);
        }

    }
```

Can you spot the UB above?

The line that causes all the problems is `p->cc = (int)(ep - bp)`.

// explain why

## The Good

In the best-case scenario, the compiler compiles `(ep - bp)` into an unsigned integer subtraction instruction, the resulting integer underflow is coerced by the `(int)` cast into a negative value, and everything is hunky dory--the resulting `(p->cc < 0)` check behaves as intended to return a zero-length buffer.

This is probably the behavior the authors envisioned when writing this code--and, to be honest, it seems to be the behavior when compiling with GCC/Clang and running with an X86 or ARM CPU.

## The Bad

Not all compilers handle pointer operations with unsigned instructions--and not all CPU instruction sets gracefully handle signed integer overflow. For instance, the MIPS architecture's `add` and `sub` instructions both trap on signed overflow, and plenty of other architectures have optional trap behavior as well. In these cases, libpcap will crash when it receives a packet with a length that is not a multiple of the `BPF_WORDALIGN()` alignment value.

## The (Hypothetical) Ugly

To my limited knowledge, I haven't seen an instruction set or compiler that would handle the `(ep - bp)` underflow in such a way that it produces a positive value. But it's not inconceivable.

*insert inconceivable gif here*

The size of an `int` type is implementation defined--there's no maximum bit-length to what it could be. The C standard _does_ require that casting a pointer to a sufficiently large integer type be well-defined. So, some future compiler *could* define `int` to be 

