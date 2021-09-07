# Development Plan

## Todo List

While we have successfully migrated StochFuzz to a new system design, we can still improve StochFuzz from multiple places.

+ [x] __NEW SYSTEM DESIGN__ (daemon), which separates AFL and StochFuzz and makes advanced fuzzing possible.
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
+ [x] A better frontend for passing arguments.
+ [x] Use runtime arguments to set different modes, instead of makefile.
+ [x] Use simple linear disassembly to check the existence of inlined data.
+ [x] Read PLT table to get library functions' names, and support the white-list for library functions.
+ [x] Correctly handle timeout from AFL.
+ [x] Use shared memory for .text section, to avoid the expensive patch commands.
+ [x] Support self-correction procedure (delta debugging).
+ [x] Support non-return analysis on UCFG, with the help of the white-list for library functions.
+ [x] Support the on-the-fly probability recalculation.
+ [x] Add a new flag/option to enable early instrumentation for fork server (i.e., before the entrypoint of binary).
+ [x] Enable periodic checking (for coverage feedback) to determine those false postives which do not lead to crashes.
+ [x] Add tailed invalid instructions for those basic blocks terminated by bad decoding.
+ [x] Add a license.
+ [x] Do not use a global sys\_config, but put the options into each object.
+ [x] Current TP\_EMIT is only compatible with fuzzers compiled with AFL\_MAP\_SIZE = (1 << 16), we need to change the underlying implementation of TP\_EMIT to automatically fit the AFL\_MAP\_SIZE.
+ [ ] Use g\_hash\_table\_iter\_init instead of g\_hash\_table\_get\_keys.
+ [ ] Apply AddrDict to all possible places..
+ [ ] Apply Iter to all possible places..
+ [ ] Support other disassembly backends (for the initial disassembly).
+ [ ] Calculate [entropy](https://github.com/NationalSecurityAgency/ghidra/issues/1035) to check the existence of inlined data (ADVANCED).
+ [ ] Fix the bugs when rewriting PIE binary and support it.
+ [ ] Remove legacy code (e.g., the function of building bridges by Rewriter is no longer supported).
+ [ ] Instead of patching a fixed invalid instruction (0x2f), randomly choose an invalid instruction to patch. More details can be found [here](http://ref.x86asm.net/coder64.html).
+ [ ] Automatically scale the number of executions triggering checking runs (based on the result of previous checking run).
+ [ ] Set the default log level as WARN (note that we need to update `make test` and `make benchmark`).
+ [ ] Use a general method to add segments in the given ELF instead of using the simple PT\_NOTE trick.
+ [ ] Fix the failed Github Actions on Ubuntu 20.04 (the root cause is unknown currently).
+ [ ] Place `ENDBR64` instruction before the AFL trampoline. The phantom program will crash otherwise.


## Challenges

We additionally have some challenges which may cause troubles or make StochFuzz not that easy to use. We are trying to resolve them.

+ The fixed LOOKUP\_TABLE\_ADDR is mixed with other random addresses, which may cause bugs in PIE binary.
+ The glibc code contains some overlapping instructions (e.g., the [instructions with the LOCK prefix](https://code.woboq.org/userspace/glibc/sysdeps/x86/atomic-machine.h.html#_M/__arch_c_compare_and_exchange_val_8_acq)), which may cause troubles for the patcher and pdisasm.

There are some other challenges introduced by the [new system design](system.md).

+ The input file may be changed by the previous crashed executing, which makes the next execution incorrect. But it seems ok in practice, because fuzzing is a highly repeative procedure which can fix the incorrect feedback automatically and quickly.
+ Timeout needs to be set up separately for AFL and StochFuzz, which may bother the users a little bit.
+ The auto-scaled timeout of AFL may cause incorrect error diagnosis (the [dd\_status](https://github.com/ZhangZhuoSJTU/StochFuzz/blob/master/src/diagnoser.h#L91) may be invalid), so it is highly recommended to specify a timeout (>= 1000ms or >= AFL\_HANG\_TMOUT if set) for AFL by `-t` option, to disable the feature of auto-scaled timeout.

Note that in the old design, we can fully control AFL, so that we can _create a new input file for the next execution_, _use the same timeout_, or _disable the auto-scaled timeout_ to avoid aforementioned challenges.

## Pending Development Decisions

Currently, there are many steps which we are hesitating to take. We may need to carefully evaluate them. __If you have any suggestion, please kindly let us know__. We are happy to take any possible discussion about improving StochFuzz.

+ Currently, we use a lookup table to translate indirect call/jump on the fly. We are not sure whether it is necessary because simply patching a jump instruction at the target address may also work well. Note that a large lookup table may increase the cache missing rate and the overhead of process forking.
+ For now, to support the [advanced strategy](https://github.com/ZhangZhuoSJTU/StochFuzz#advanced-usage), we maintain a retaddr mapping and do _O(log n)_ online binary searching to find the original retaddr when unwinding stack. It may be better to maintain a retaddr lookup table which supports _O(1)_ looking up. But also, this lookup table will extremely increase the memory usage as well as the cache missing rate and the overhead of process forking.
+ Hook more signals to collect address information for a better error diagnosis, which, on the other hand, may cause conflicts of signal handlers set by the subject program.
