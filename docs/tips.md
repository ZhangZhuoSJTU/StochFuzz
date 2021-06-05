# Tips

To enable a more effective and efficient fuzzing, we provide several tips about better using StochFuzz. 

## Advanced Strategy

As mentioned in [README.md](../README.md#advanced-usage), we recommend every user first tries the advanced strategy.

StochFuzz tries to provide a conservative rewriting. As such, it emulates all the _CALL_ instructions to maintain an unchanged data flow. 

However, in most cases, the return addresses pushed by _CALL_ instructions are only used by _RET_ instructions and the stack unwinding. Based on this observation, we provide an advanced rewriting strategy that hooks the process of stack unwinding and hence does not need to emulate _CALL_ instructions. This strategy is quite efficient and can reduce around 80% overhead of StochFuzz.

The advanced strategy can be applied to most binaries but will cause rewriting errors on some including:

+ statically-linked binaries that do online stack unwinding
+ some CFI-protected binaries
+ some go-written binary
+ ...

How to adopt the advanced rewriting strategy can be found in [README.md](../README.md#advanced-usage).

## Timeout

StochFuzz needs to specify a timeout for any execution caused by the increment rewriting. The timeout is configured by the `-t` option.

```
  -t msec       - set the timeout for each daemon-triggering execution
                  set it as zero to ignore the timeout (default: 2000 ms)
```

AFL, or any attached AFL-based fuzzer, needs to specify a timeout either. We recommend that the two timeouts should be set consistently, but it is not mandatory. 

However, for the binaries with inlined data, the timeout set for the attached fuzzer should __be larger than 1000ms__. Otherwise, the auto-scaling feature of AFL timeout will cause incorrect error diagnosis during the stochastic rewriting. 

## Checking Executions

As we mentioned in [system.md](system.md), we adopt a new system design to have a wide application in the fields of binary-only fuzzing. This new architecture design is enabled by the observation that we only need to instrument an instruction per basic block to collect the code coverage of AFL and is facilitated by a new technique named checking executions. 

Technically speaking, checking executions are triggered periodically and to check whether the collected coverages are consistent with and without uncertain patches. 

The `-x` option is provided for configuring the checking executions, setting the number of executions after which a checking execution will be triggered.  

```
  -x execs      - set the number of executions after which a checking run will be triggered
                  set it as zero to disable checking runs (default: 200000)
```

For example, if we provide `-x 1000`, it means a checking execution will be triggered every 1000 AFL executions. 

The period of checking executions affects the fuzzing effectiveness. Intuitively, the more checking executions we have, the more overhead they cause. The overhead caused by checking executions is <img src="https://render.githubusercontent.com/render/math?math=\large \frac{1}{M}">
, where a checking execution is triggered every _M_ normal executions.

The period of checking executions also affects the probabilistic soundness we provided. Let's additionally assume that the probability of a given rewriting error changing the execution path is _p_. Then, we will have that, the probability _P_ that a rewriting error cannot be detected after the total _N_ executions is <img src="https://render.githubusercontent.com/render/math?math=\large (1 - p)^\frac{N}{M}">.

In a nutshell, the larger number we set, the fewer check executions we will take. In other words, the larger number we set, the more cost-effective but the less probabilistically sound the fuzzing is.

For example, if _M = 1000_, _p = 1e-4_, _N = 1e8_. The overhead caused by checking executions is _0.1%_ and the probability of have an undetected rewriting error is _4.5e-5_.

The user may need to provide a suitable number. __A number larger than 200 is recommended__. 

Note that this option is useful only when the inlined data is presented. To eliminate the overhead caused by checking executions, we additionally plan to set up two different fuzzing instances like what [QSYM](https://github.com/sslab-gatech/qsym) does, where one is for fuzzing and the other is for checking executions.
