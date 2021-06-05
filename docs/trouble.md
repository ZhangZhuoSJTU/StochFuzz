# Troubleshootings

This documentation mainly talks about how to handle inputs that cause inconsistent behaviors on the rewritten binaries (e.g., invalid crashes which cannot be reproduced by the original binaries). Please kindly open an issue to report any other problems, including:

+ The execution speed is quite slow (e.g., slower than AFL-QEMU)
+ The fuzzing process is stuck (i.e., the AFL panel does not have updates for a while)
+ StochFuzz crashes during rewriting
+ ...

## How to check whether an input will cause inconsistent behaviors.

As mentioned in [README.md](../README.md#basic-usage), after the initial rewriting, StochFuzz will generate a _phantom file_. Originally, if we want to do binary-only fuzzing, we attach AFL to this phantom binary. 

Actually, this phantom binary can also be directly executed, with the same arguments as the original binary has. 

Hence, to check whether an input will cause inconsistent behaviors, you can execute both the original binary and the phantom binary with the given input and check the behaviors of two binaries.

## Incorrect rewriting options or latent bugs in StochFuzz?

StochFuzz provides different rewriting options and will automatically choose some, based on the given binary. In some cases, StochFuzz may do the wrong choices. The following steps can help us identify whether the erroneous behaviors are caused by incorrect rewriting options or latent bugs in StochFuzz.

+ If you adopt the advanced strategy, please remove all cached files (`rm .*`) and try the basic usage.
+ If the erroneous behaviors still exist after adopting the basic usage, please remove all cached files (`rm .*`) and feed `-e -f -i` options into StochFuzz.

```
  -e            - install the fork server at the entrypoint instead of the main function
  -f            - forcedly assume there is data interleaving with code
  -i            - ignore the call-fallthrough edges to defense RET-misusing obfuscation
```

+ If the erroneous behaviors still exist after rewriting with the aforementioned options, please kindly open an issue to let us know.


## Known issues

+ Like [AFL](https://github.com/google/AFL/blob/fab1ca5ed7e3552833a18fc2116d33a9241699bc/README.md#13-known-limitations--areas-for-improvement), StochFuzz cannot handle programs that install custom handlers for some important signals (SIGSEGV, SIGABRT, etc). Moreover, StochFuzz additionally occupies one more signal, _SIGUSR1_. If the subject program has a custom handler for SIGUSR1, the user may need to modify StochFuzz to use SIGUSR2 or other unused signals.
