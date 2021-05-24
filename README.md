# StochFuzz: A New Binary-only Fuzzing Solution

[![test](https://github.com/ZhangZhuoSJTU/StochFuzz/actions/workflows/basic.yml/badge.svg)](https://github.com/ZhangZhuoSJTU/StochFuzz/actions/workflows/basic.yml)
[![benchmark](https://github.com/ZhangZhuoSJTU/StochFuzz/actions/workflows/benchmark.yml/badge.svg)](https://github.com/ZhangZhuoSJTU/StochFuzz/actions/workflows/benchmark.yml)

<p>
<a href="https://www.cs.purdue.edu/homes/zhan3299/res/SP21b.pdf"> <img title="" src="imgs/paper.png" alt="loading-ag-167" align="right" width="200"></a>

StochFuzz is a (probabilistically) sound and cost-effective fuzzing technique for stripped binaries. It is facilitated by a novel incremental and stochastic rewriting technique that is particularly suitable for binary-only fuzzing. Any AFL-based fuzzer, which takes edge coverage (defined by AFL) as runtime feedback, can acquire benefits from StochFuzz to directly fuzz stripped binaries.
</p>
  
More data and the results of the experiments can be found [here](https://github.com/ZhangZhuoSJTU/StochFuzz-data).

## Building StochFuzz

The dependences of StochFuzz can be built by [build.sh](https://github.com/ZhangZhuoSJTU/StochFuzz/blob/master/build.sh).
 
```bash
$ git clone https://github.com/ZhangZhuoSJTU/StochFuzz.git
$ cd StochFuzz
$ ./build.sh
```

StochFuzz itself can be built by GNU Make.

```bash
$ cd src
$ make release
```

## How to Use

StochFuzz provides multiple rewriting options, which follows the AFL's style of passing arguments. Details can be found at [options.md](docs/options.md).

```
$ ./stoch-fuzz -h
stoch-fuzz 1.0.0 by <zhan3299@purdue.edu>

./stoch-fuzz [ options ] -- target_binary [ ... ]

Mode settings:

  -S            - start a background daemon and wait for a fuzzer to attach (defualt mode)
  -R            - dry run target_binary with given arguments without an attached fuzzer
  -P            - patch target_binary without incremental rewriting
  -D            - probabilistic disassembly without rewriting
  -V            - show currently observed breakpoints

Rewriting settings:

  -g            - trace previous PC
  -c            - count the number of basic blocks with conflicting hash values
  -d            - disable instrumentation optimization
  -r            - assume the return addresses are only used by RET instructions
  -e            - install the fork server at the entrypoint instead of the main function
  -f            - forcedly assume there is data interleaving with code
  -i            - ignore the call-fallthrough edges to defense RET-misusing obfuscation

Other stuff:

  -h            - print this help
  -x execs      - set the number of executions after which a checking run will be triggered
                  set it as zero to disable checking runs (default: 200000)
  -t msec       - set the timeout for each daemon-triggering execution
                  set it as zero to ignore the timeout (default: 2000 ms)
  -l level      - set the log level, including INFO, WARN, ERROR, and FATAL (default: INFO)

```

### Basic Usage

To fuzz a stripped binary, namely `example.out`, we need to `cd` to the directory of the target binary. For example, if the full path of `example.out` is `/root/example.out`, we need to first `cd /root/`. This restriction is due to some design faults and we will try to relax it in the future. 

Assuming StochFuzz is located at `/root/StochFuzz/src/stoch-fuzz`, execute the following command to start rewriting the target binary.

```bash
$ cd /root/
$ /root/StochFuzz/src/stoch-fuzz -- example.out # do not use ./example.out here
```

After the initial rewriting, we will get a phantom file named `example.out.phantom`. This phantom file can be directly fuzzed by AFL or any AFL-based fuzzer. Note that the StochFuzz process would not stop during fuzzing, so please make sure the process is alive during fuzzing.

Here is a demo that shows how StochFuzz works.

[![asciicast](https://asciinema.org/a/415985.svg)](https://asciinema.org/a/415985)

## TODO List
Todo list can be found [here](TODO.md).
