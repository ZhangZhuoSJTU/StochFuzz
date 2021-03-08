## Todo

+ [x] In release version, remove unnecessary z\_log (e.g., z\_debug, z\_trace, and etc.).
+ [x] Support probabilisitic disassembly.
+ [x] Mark .text section non-writable.
+ [x] Support C++ exceptions (via pushing the original ret\_addr onto the stack).
+ [x] When a CP\_RETADDR is found, support updating other CP\_RETADDR from the same callee.
+ [x] Use-def analysis on EFLAG register to avoid unnecessary context switching.
+ [x] Support pre-disassembly (linear disassembly) -- IT SEEMS NOT A GOOD IDEA.
+ [x] Support `jrcxz` and `jecxz` instructions.
+ [x] It may be a good idea to additionally hook SIGILL caused by mis-patched instructions. In that design, exiting the program with a specific status code (in SIGSEGV handler) is a better approach, compared with raising SIGILL. It can also avoid recursive signal handling.
+ [x] Support retaddr patch when pdisasm is enabled (check retaddr's probability) -- it seems impossible. Note that we cannot guarantee the control flow is returned from the callee even the returen address is visited.
+ [x] __NEW SYSTEM DESIGN__ (daemon), which separates AFL and StochFuzz and makes advanced fuzzing possible.
+ [x] A better frontend for passing arguments.
+ [ ] Use runtime arguments to set different modes, instead of makefile.
+ [ ] Use g\_hash\_table\_iter\_init instead of g\_hash\_table\_get\_keys.
+ [ ] Apply AddrDict to all possible places..
+ [ ] Apply Iter to all possible places..
+ [ ] Read PLT table to get library functions' names, and support the white-list for library functions.
+ [ ] Correctly handle timeout from AFL.
+ [ ] Use shared memory for .text section, to avoid the expensive patch commands.
+ [ ] Support self-correction procedure (delta debugging).
+ [ ] Reduce false positive in recursive disassembly. A possible solution is to have a non-return analysis, with the help of the white-list for library functions .
+ [ ] Support the on-the-fly probability recalculation.
+ [ ] Support other disassembly backends (for the initial disassembly).
+ [x] Use simple linear disassembly to check the existence of inlined data.
+ [ ] Calculate [entropy](https://github.com/NationalSecurityAgency/ghidra/issues/1035) to check the existence of inlined data (ADVANCED).

## Known Issues

+ Fixed LOOKUP\_TABLE\_ADDR is mixed with other random addresses, may cause bugs in PIE binary.
+ When running, the input file may be modified by previous crashed run (due to the new system design).
+ Timeout needs to be set up separately for AFL and StochFuzz (due to the new system design).

## Tag Info

+ v0.1.0: apply the new system design and test the new StochFuzz with all benchmarks mentioned in the paper.
+ v0.2.0: adopt a better frontend to parse arguments and automatically decide whether we need a complete probabilistic disassembly.
