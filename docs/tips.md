# Tips

To enable a more effective and efficient fuzzing, we provide several tips about better using StochFuzz. 

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

The user may need to provide a suitable number. __A number between 200 and 2000 is recommended__. 

Note that this option is useful only when the inlined data is presented. To eliminate the overhead caused by checking executions, we additionally plan to set up two different fuzzing instances like what [QYSM](https://github.com/sslab-gatech/qsym) does, where one is for fuzzing and the other is for checking executions.
