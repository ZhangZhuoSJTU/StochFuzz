## Todo

While we are migrating StochFuzz to a new system design, followings are some to-do tasks.

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
+ [x] Use runtime arguments to set different modes, instead of makefile.
+ [ ] Use g\_hash\_table\_iter\_init instead of g\_hash\_table\_get\_keys.
+ [ ] Apply AddrDict to all possible places..
+ [ ] Apply Iter to all possible places..
+ [ ] Read PLT table to get library functions' names, and support the white-list for library functions.
+ [x] Correctly handle timeout from AFL.
+ [x] Use shared memory for .text section, to avoid the expensive patch commands.
+ [x] Support self-correction procedure (delta debugging).
+ [ ] Support non-return analysis on UCFG, with the help of the white-list for library functions.
+ [ ] Support the on-the-fly probability recalculation.
+ [ ] Support other disassembly backends (for the initial disassembly).
+ [x] Use simple linear disassembly to check the existence of inlined data.
+ [ ] Calculate [entropy](https://github.com/NationalSecurityAgency/ghidra/issues/1035) to check the existence of inlined data (ADVANCED).
+ [ ] Fix the bugs when rewriting PIE binary and support it.
+ [ ] When SINGLE\_SUCC\_OPT is enabled and sys\_config.disable\_opt is not set, remove the AFL trampoline before each function entrypoint.
+ [x] Add tailed invalid instructions for those basic blocks terminated by bad decoding.
+ [ ] Remove legacy code (e.g., the function of building bridges by Rewriter is no longer supported).
+ [ ] Add a new flag/option to enable early instrumentation for fork server (i.e., before the entrypoint of binary).
+ [ ] Enable periodic checking (for coverage feedback) to determine those false postives which do not lead to crashes.

## Known Issues

There are some known issues which we are trying to resolve.

+ Fixed LOOKUP\_TABLE\_ADDR is mixed with other random addresses, may cause bugs in PIE binary.
+ When running, the input file may be modified by previous crashed run (due to the new system design).
+ Timeout needs to be set up separately for AFL and StochFuzz (due to the new system design).
+ Test failed on Github Actions Ubuntu 20.04 (the root cause is unknown currently).
+ The auto-scaled timeout of AFL may cause incorrect error diagnosis (the dd\_status may change), so it is recommended to specify a timeout (>= 1000ms or >= AFL\_HANG\_TMOUT if set) to AFL by -t option.
+ Self correction procedure may encounter problems under dry run mode (-R) due to ASLR.

## Undecided Changes

+ Hook more signals to collect address information and send real signal in the meantime.

## Tag Info

We have marked multiple tags when migrating the system, many of which reflect the migration progress.

+ v0.1.0: apply the new system design and test the new StochFuzz with all benchmarks mentioned in the paper.
+ v0.2.0: adopt a better frontend to parse arguments and automatically decide whether we need a complete probabilistic disassembly.
+ v0.3.0: support timeout for daemon and add benchmark testing for each tag.
+ v0.4.0: support shared .text section for the new system design and simplify the communication between the daemon and binary.
+ v0.5.0: support automatically fixing overlapped bridges (i.e., patched *jmp* instructions in the original code space).
+ v0.6.0: support self correction procedure.
