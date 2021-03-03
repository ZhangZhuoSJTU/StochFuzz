; Boogie universal background predicate
; Copyright (c) 2004-2010, Microsoft Corp.
(set-info :category "industrial")
(declare-sort |T@U| 0)
(declare-sort |T@T| 0)
(declare-fun real_pow (Real Real) Real)
(declare-fun UOrdering2 (|T@U| |T@U|) Bool)
(declare-fun UOrdering3 (|T@T| |T@U| |T@U|) Bool)

(declare-fun tickleBool (Bool) Bool)
(assert (and (tickleBool true) (tickleBool false)))
(declare-fun TV (Int) Bool)
(declare-fun TO (Int) Bool)
(declare-fun between (Int Int Int) Bool)
(declare-fun word (Int) Bool)
(declare-fun WORD_HI () Int)
(declare-fun NULL () Int)
(declare-fun TVM (Int Int) Bool)
(declare-fun Mult (Int Int) Int)
(declare-fun TVM3 (Int Int Int) Bool)
(declare-fun memAddr (Int) Bool)
(declare-fun ?memLo () Int)
(declare-fun ?memHi () Int)
(declare-fun memAddrEx (Int) Bool)
(declare-fun TBV ((_ BitVec 32)) Bool)
(declare-fun $Aligned ((_ BitVec 32)) Bool)
(declare-fun $bbvec4 ((Array Int Int) Int Int (Array Int Int) Int Int Int Int Int) Bool)
(declare-fun B (Int) (_ BitVec 32))
(declare-fun I ((_ BitVec 32)) Int)
(declare-fun $bb2vec4 ((Array Int Int) Int (Array Int Int) Int Int Int Int Int) Bool)
(declare-fun q@and (Int Int) Int)
(declare-fun q@or (Int Int) Int)
(declare-fun q@xor (Int Int) Int)
(declare-fun shl (Int Int) Int)
(declare-fun shr (Int Int) Int)
(declare-fun neg (Int) Int)
(declare-fun Aligned (Int) Bool)
(declare-fun %lbl%+2849 () Bool)
(declare-fun %lbl%@4150 () Bool)
(declare-fun $x () (_ BitVec 32))
(declare-fun %lbl%+4132 () Bool)
(assert (forall ((val Int) ) (! (= (TV val) true)
 :qid |baseibpl.14:28|
 :skolemid |0|
 :pattern ( (TV val))
)))
(assert (forall ((wordOffset Int) ) (! (= (TO wordOffset) true)
 :qid |baseibpl.18:28|
 :skolemid |1|
 :pattern ( (TO wordOffset))
)))
(assert (forall ((i1 Int) (i2 Int) (x Int) ) (! (= (between i1 i2 x) (and
(<= i1 x)
(< x i2)))
 :qid |baseibpl.25:18|
 :skolemid |2|
 :pattern ( (between i1 i2 x))
)))
(assert (forall ((val@@0 Int) ) (! (= (word val@@0) (and
(<= 0 val@@0)
(< val@@0 WORD_HI)))
 :qid |baseibpl.30:15|
 :skolemid |3|
 :pattern ( (word val@@0))
)))
(assert (= NULL 0))
(assert (forall ((a Int) (b Int) ) (! (= (TVM a b) true)
 :qid |baseibpl.45:29|
 :skolemid |4|
 :pattern ( (TVM a b))
)))
(assert (forall ((a@@0 Int) (b@@0 Int) ) (! (= (Mult a@@0 b@@0) (* a@@0 b@@0))
 :qid |baseibpl.47:15|
 :skolemid |5|
 :pattern ( (TVM a@@0 b@@0))
)))
(assert (forall ((a@@1 Int) (b1 Int) (b2 Int) ) (! (= (TVM3 a@@1 b1 b2) true)
 :qid |baseibpl.49:30|
 :skolemid |6|
 :pattern ( (TVM3 a@@1 b1 b2))
)))
(assert (forall ((i Int) ) (! (= (memAddr i) (and
(<= ?memLo i)
(< i ?memHi)))
 :qid |memoryib.18:18|
 :skolemid |7|
 :pattern ( (memAddr i))
)))
(assert (forall ((i@@0 Int) ) (! (= (memAddrEx i@@0) (and
(<= ?memLo i@@0)
(<= i@@0 ?memHi)))
 :qid |memoryib.19:20|
 :skolemid |8|
 :pattern ( (memAddrEx i@@0))
)))
(assert (forall ((b@@1 (_ BitVec 32)) ) (! (= (TBV b@@1) true)
 :qid |BitVecto.18:29|
 :skolemid |9|
 :pattern ( (TBV b@@1))
)))
(assert (forall ((b@@2 (_ BitVec 32)) ) (! (= ($Aligned b@@2) (= (bvand b@@2 #x00000003) #x00000000))
 :qid |BitVecto.12:19|
 :skolemid |10|
 :pattern ( ($Aligned b@@2))
)))
(assert (forall ((a@@2 (Array Int Int)) (off Int) (aBase Int) (bb (Array Int Int)) (i0 Int) (i1@@0 Int) (i2@@0 Int) (g1 Int) (g2 Int) ) (! (= ($bbvec4 a@@2 off aBase bb i0 i1@@0 i2@@0 g1 g2) (forall ((i@@1 Int) ) (! (=> (and
(TV i@@1)
(word (- i@@1 i0))
(<= i1@@0 i@@1)
(< i@@1 i2@@0)
($Aligned (B (- i@@1 i0)))) (and
(between g1 g2 (+ g1 (* 4 (I (bvlshr (B (- i@@1 i0)) #x00000007)))))
(= (= (select a@@2 (+ aBase (- i@@1 i0))) off) (= #x00000000 (bvand (B (select bb (+ g1 (* 4 (I (bvlshr (B (- i@@1 i0)) #x00000007)))))) (bvshl #x00000001 (bvand (bvlshr (B (- i@@1 i0)) #x00000002) #x0000001f)))))))
 :qid |BitVecto.19:11|
 :skolemid |11|
 :pattern ( (TV i@@1))
)))
 :qid |BitVecto.17:18|
 :skolemid |12|
 :pattern ( ($bbvec4 a@@2 off aBase bb i0 i1@@0 i2@@0 g1 g2))
)))
(assert (forall ((a@@3 (Array Int Int)) (aBase@@0 Int) (bb@@0 (Array Int Int)) (i0@@0 Int) (i1@@1 Int) (i2@@1 Int) (g1@@0 Int) (g2@@0 Int) ) (! (= ($bb2vec4 a@@3 aBase@@0 bb@@0 i0@@0 i1@@1 i2@@1 g1@@0 g2@@0) (forall ((i@@2 Int) ) (! (=> (and
(TV i@@2)
(word (- i@@2 i0@@0))
(<= i1@@1 i@@2)
(< i@@2 i2@@1)
($Aligned (B (- i@@2 i0@@0)))) (and
(between g1@@0 g2@@0 (+ g1@@0 (* 4 (I (bvlshr (B (- i@@2 i0@@0)) #x00000006)))))
(= (B (select a@@3 (+ aBase@@0 (- i@@2 i0@@0)))) (bvand (bvlshr (B (select bb@@0 (+ g1@@0 (* 4 (I (bvlshr (B (- i@@2 i0@@0)) #x00000006)))))) (bvand (bvlshr (B (- i@@2 i0@@0)) #x00000001) #x0000001f)) #x00000003))))
 :qid |BitVecto.28:11|
 :skolemid |13|
 :pattern ( (TV i@@2))
)))
 :qid |BitVecto.26:19|
 :skolemid |14|
 :pattern ( ($bb2vec4 a@@3 aBase@@0 bb@@0 i0@@0 i1@@1 i2@@1 g1@@0 g2@@0))
)))
(assert (= WORD_HI (+ (+ 2147483647 2147483647) 2)))
(assert (= (I #x00000001) 1))
(assert (forall ((i1@@2 Int) (i2@@2 Int) ) (! (=> (and
(word i1@@2)
(word i2@@2)) (= (= i1@@2 i2@@2) (= (B i1@@2) (B i2@@2))))
 :qid |BitVecto.9:15|
 :skolemid |19|
 :pattern ( (B i1@@2) (B i2@@2))
)))
(assert (forall ((b1@@0 (_ BitVec 32)) (b2@@0 (_ BitVec 32)) ) (! (= (= b1@@0 b2@@0) (= (I b1@@0) (I b2@@0)))
 :qid |BitVecto.10:15|
 :skolemid |20|
 :pattern ( (I b1@@0) (I b2@@0))
)))
(assert (forall ((b@@3 (_ BitVec 32)) ) (! (word (I b@@3))
 :qid |BitVecto.12:15|
 :skolemid |21|
 :pattern ( (I b@@3))
)))
(assert (forall ((b@@4 (_ BitVec 32)) ) (! (= (B (I b@@4)) b@@4)
 :qid |BitVecto.13:15|
 :skolemid |22|
 :pattern ( (B (I b@@4)))
)))
(assert (forall ((i@@3 Int) ) (! (=> (word i@@3) (= (I (B i@@3)) i@@3))
 :qid |BitVecto.14:15|
 :skolemid |23|
 :pattern ( (I (B i@@3)))
)))
(assert (forall ((b1@@1 (_ BitVec 32)) (b2@@1 (_ BitVec 32)) ) (! (=> (word (+ (I b1@@1) (I b2@@1))) (= (+ (I b1@@1) (I b2@@1)) (I (bvadd b1@@1 b2@@1))))
 :qid |BitVecto.16:15|
 :skolemid |24|
 :pattern ( (bvadd b1@@1 b2@@1))
 :pattern ( (TBV b1@@1) (TBV b2@@1))
)))
(assert (forall ((b1@@2 (_ BitVec 32)) (b2@@2 (_ BitVec 32)) ) (! (=> (word (- (I b1@@2) (I b2@@2))) (= (- (I b1@@2) (I b2@@2)) (I (bvsub b1@@2 b2@@2))))
 :qid |BitVecto.17:15|
 :skolemid |25|
 :pattern ( (bvsub b1@@2 b2@@2))
 :pattern ( (TBV b1@@2) (TBV b2@@2))
)))
(assert (forall ((b1@@3 (_ BitVec 32)) (b2@@3 (_ BitVec 32)) ) (! (=> (word (* (I b1@@3) (I b2@@3))) (= (* (I b1@@3) (I b2@@3)) (I (bvmul b1@@3 b2@@3))))
 :qid |BitVecto.18:15|
 :skolemid |26|
 :pattern ( (bvmul b1@@3 b2@@3))
 :pattern ( (TBV b1@@3) (TBV b2@@3))
)))
(assert (forall ((b1@@4 (_ BitVec 32)) (b2@@4 (_ BitVec 32)) ) (! (= (<= (I b1@@4) (I b2@@4)) (bvule b1@@4 b2@@4))
 :qid |BitVecto.19:15|
 :skolemid |27|
 :pattern ( (bvule b1@@4 b2@@4))
 :pattern ( (TBV b1@@4) (TBV b2@@4))
)))
(assert (forall ((i1@@3 Int) (i2@@3 Int) ) (! (= (q@and i1@@3 i2@@3) (I (bvand (B i1@@3) (B i2@@3))))
 :qid |BitVecto.20:15|
 :skolemid |28|
 :pattern ( (q@and i1@@3 i2@@3))
)))
(assert (forall ((i1@@4 Int) (i2@@4 Int) ) (! (= (q@or i1@@4 i2@@4) (I (bvor (B i1@@4) (B i2@@4))))
 :qid |BitVecto.21:15|
 :skolemid |29|
 :pattern ( (q@or i1@@4 i2@@4))
)))
(assert (forall ((i1@@5 Int) (i2@@5 Int) ) (! (= (q@xor i1@@5 i2@@5) (I (bvxor (B i1@@5) (B i2@@5))))
 :qid |BitVecto.22:15|
 :skolemid |30|
 :pattern ( (q@xor i1@@5 i2@@5))
)))
(assert (forall ((i1@@6 Int) (i2@@6 Int) ) (! (= (shl i1@@6 i2@@6) (I (bvshl (B i1@@6) (B i2@@6))))
 :qid |BitVecto.23:15|
 :skolemid |31|
 :pattern ( (shl i1@@6 i2@@6))
)))
(assert (forall ((i1@@7 Int) (i2@@7 Int) ) (! (= (shr i1@@7 i2@@7) (I (bvlshr (B i1@@7) (B i2@@7))))
 :qid |BitVecto.24:15|
 :skolemid |32|
 :pattern ( (shr i1@@7 i2@@7))
)))
(assert (forall ((i@@4 Int) ) (! (= (neg i@@4) (I (bvnot (B i@@4))))
 :qid |BitVecto.25:15|
 :skolemid |33|
 :pattern ( (neg i@@4))
)))
(assert (forall ((b@@5 (_ BitVec 32)) ) (! (= (Aligned (I b@@5)) (= (bvand b@@5 #x00000003) #x00000000))
 :qid |BitVecto.27:15|
 :skolemid |34|
 :pattern ( (Aligned (I b@@5)))
)))
(push 1)
(set-info :boogie-vc-id _aligned)
(assert (not
(let ((anon0_correct (=> (! (and %lbl%+2849 true) :lblpos +2849) (and
(! (or %lbl%@4150 ($Aligned (bvmul #x00000004 $x))) :lblneg @4150)
(=> ($Aligned (bvmul #x00000004 $x)) true)))))
(let ((PreconditionGeneratedEntry_correct (=> (! (and %lbl%+4132 true) :lblpos +4132) anon0_correct)))
PreconditionGeneratedEntry_correct))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2852 () Bool)
(declare-fun %lbl%@4178 () Bool)
(declare-fun %lbl%+4172 () Bool)
(push 1)
(set-info :boogie-vc-id _zeroAligned)
(assert (not
(let ((anon0_correct@@0 (=> (! (and %lbl%+2852 true) :lblpos +2852) (and
(! (or %lbl%@4178 ($Aligned #x00000000)) :lblneg @4178)
(=> ($Aligned #x00000000) true)))))
(let ((PreconditionGeneratedEntry_correct@@0 (=> (! (and %lbl%+4172 true) :lblpos +4172) anon0_correct@@0)))
PreconditionGeneratedEntry_correct@@0))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2858 () Bool)
(declare-fun %lbl%@4199 () Bool)
(declare-fun $x@@0 () (_ BitVec 32))
(declare-fun %lbl%+4183 () Bool)
(push 1)
(set-info :boogie-vc-id _andAligned)
(assert (not
(let ((anon0_correct@@1 (=> (! (and %lbl%+2858 true) :lblpos +2858) (and
(! (or %lbl%@4199 (= (= (bvand $x@@0 #x00000003) #x00000000) ($Aligned $x@@0))) :lblneg @4199)
(=> (= (= (bvand $x@@0 #x00000003) #x00000000) ($Aligned $x@@0)) true)))))
(let ((PreconditionGeneratedEntry_correct@@1 (=> (! (and %lbl%+4183 true) :lblpos +4183) anon0_correct@@1)))
PreconditionGeneratedEntry_correct@@1))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2867 () Bool)
(declare-fun %lbl%@4234 () Bool)
(declare-fun $x@@1 () (_ BitVec 32))
(declare-fun $y () (_ BitVec 32))
(declare-fun %lbl%+4216 () Bool)
(push 1)
(set-info :boogie-vc-id _addAligned)
(assert (not
(let ((anon0_correct@@2 (=> (! (and %lbl%+2867 true) :lblpos +2867) (and
(! (or %lbl%@4234 (=> ($Aligned $x@@1) (= ($Aligned $y) ($Aligned (bvadd $x@@1 $y))))) :lblneg @4234)
(=> (=> ($Aligned $x@@1) (= ($Aligned $y) ($Aligned (bvadd $x@@1 $y)))) true)))))
(let ((PreconditionGeneratedEntry_correct@@2 (=> (! (and %lbl%+4216 true) :lblpos +4216) anon0_correct@@2)))
PreconditionGeneratedEntry_correct@@2))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2876 () Bool)
(declare-fun %lbl%@4273 () Bool)
(declare-fun $x@@2 () (_ BitVec 32))
(declare-fun $y@@0 () (_ BitVec 32))
(declare-fun %lbl%+4255 () Bool)
(push 1)
(set-info :boogie-vc-id _subAligned)
(assert (not
(let ((anon0_correct@@3 (=> (! (and %lbl%+2876 true) :lblpos +2876) (and
(! (or %lbl%@4273 (=> ($Aligned $x@@2) (= ($Aligned $y@@0) ($Aligned (bvsub $x@@2 $y@@0))))) :lblneg @4273)
(=> (=> ($Aligned $x@@2) (= ($Aligned $y@@0) ($Aligned (bvsub $x@@2 $y@@0)))) true)))))
(let ((PreconditionGeneratedEntry_correct@@3 (=> (! (and %lbl%+4255 true) :lblpos +4255) anon0_correct@@3)))
PreconditionGeneratedEntry_correct@@3))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2882 () Bool)
(declare-fun %lbl%@4338 () Bool)
(declare-fun $b () (_ BitVec 32))
(declare-fun %lbl%@4348 () Bool)
(declare-fun %lbl%@4358 () Bool)
(declare-fun %lbl%@4368 () Bool)
(declare-fun %lbl%+4294 () Bool)
(push 1)
(set-info :boogie-vc-id _notAligned)
(assert (not
(let ((anon0_correct@@4 (=> (! (and %lbl%+2882 true) :lblpos +2882) (and
(! (or %lbl%@4338 (not ($Aligned (bvadd $b #x00000001)))) :lblneg @4338)
(=> (not ($Aligned (bvadd $b #x00000001))) (and
(! (or %lbl%@4348 (not ($Aligned (bvadd $b #x00000002)))) :lblneg @4348)
(=> (not ($Aligned (bvadd $b #x00000002))) (and
(! (or %lbl%@4358 (not ($Aligned (bvadd $b #x00000003)))) :lblneg @4358)
(=> (not ($Aligned (bvadd $b #x00000003))) (and
(! (or %lbl%@4368 (bvule $b #xfffffffc)) :lblneg @4368)
(=> (bvule $b #xfffffffc) true)))))))))))
(let ((PreconditionGeneratedEntry_correct@@4 (=> (! (and %lbl%+4294 true) :lblpos +4294) (=> ($Aligned $b) anon0_correct@@4))))
PreconditionGeneratedEntry_correct@@4))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2888 () Bool)
(declare-fun %lbl%@4414 () Bool)
(declare-fun $x@@3 () (_ BitVec 32))
(declare-fun %lbl%@4432 () Bool)
(declare-fun %lbl%+4375 () Bool)
(push 1)
(set-info :boogie-vc-id _is4kAligned)
(assert (not
(let ((anon0_correct@@5 (=> (! (and %lbl%+2888 true) :lblpos +2888) (and
(! (or %lbl%@4414 (= (bvand (bvsub $x@@3 (bvand $x@@3 #x00000fff)) #x00000fff) #x00000000)) :lblneg @4414)
(=> (= (bvand (bvsub $x@@3 (bvand $x@@3 #x00000fff)) #x00000fff) #x00000000) (and
(! (or %lbl%@4432 (and
(bvule #x00000000 (bvand $x@@3 #x00000fff))
(bvule (bvand $x@@3 #x00000fff) #x00000fff))) :lblneg @4432)
(=> (and
(bvule #x00000000 (bvand $x@@3 #x00000fff))
(bvule (bvand $x@@3 #x00000fff) #x00000fff)) true)))))))
(let ((PreconditionGeneratedEntry_correct@@5 (=> (! (and %lbl%+4375 true) :lblpos +4375) anon0_correct@@5)))
PreconditionGeneratedEntry_correct@@5))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2894 () Bool)
(declare-fun %lbl%@4498 () Bool)
(declare-fun $x@@4 () (_ BitVec 32))
(declare-fun %lbl%@4520 () Bool)
(declare-fun %lbl%+4455 () Bool)
(push 1)
(set-info :boogie-vc-id _is2m4kAligned)
(assert (not
(let ((anon0_correct@@6 (=> (! (and %lbl%+2894 true) :lblpos +2894) (and
(! (or %lbl%@4498 (= (bvand (bvsub (bvadd $x@@4 #x00200000) (bvand $x@@4 #x001fffff)) #x00000fff) #x00000000)) :lblneg @4498)
(=> (= (bvand (bvsub (bvadd $x@@4 #x00200000) (bvand $x@@4 #x001fffff)) #x00000fff) #x00000000) (and
(! (or %lbl%@4520 (and
(bvule #x00000000 (bvand $x@@4 #x001fffff))
(bvule (bvand $x@@4 #x001fffff) #x001fffff))) :lblneg @4520)
(=> (and
(bvule #x00000000 (bvand $x@@4 #x001fffff))
(bvule (bvand $x@@4 #x001fffff) #x001fffff)) true)))))))
(let ((PreconditionGeneratedEntry_correct@@6 (=> (! (and %lbl%+4455 true) :lblpos +4455) anon0_correct@@6)))
PreconditionGeneratedEntry_correct@@6))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2900 () Bool)
(declare-fun %lbl%@4581 () Bool)
(declare-fun $x@@5 () (_ BitVec 32))
(declare-fun %lbl%@4595 () Bool)
(declare-fun %lbl%+4543 () Bool)
(push 1)
(set-info :boogie-vc-id _add4kAligned)
(assert (not
(let ((anon0_correct@@7 (=> (! (and %lbl%+2900 true) :lblpos +2900) (and
(! (or %lbl%@4581 (= (bvand (bvadd $x@@5 #x00001000) #x00000fff) #x00000000)) :lblneg @4581)
(=> (= (bvand (bvadd $x@@5 #x00001000) #x00000fff) #x00000000) (and
(! (or %lbl%@4595 ($Aligned $x@@5)) :lblneg @4595)
(=> ($Aligned $x@@5) true)))))))
(let ((PreconditionGeneratedEntry_correct@@7 (=> (! (and %lbl%+4543 true) :lblpos +4543) (=> (= (bvand $x@@5 #x00000fff) #x00000000) anon0_correct@@7))))
PreconditionGeneratedEntry_correct@@7))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+2906 () Bool)
(declare-fun %lbl%@4652 () Bool)
(declare-fun %lbl%@4662 () Bool)
(declare-fun $unitSize () (_ BitVec 32))
(declare-fun %lbl%@4676 () Bool)
(declare-fun %lbl%+4600 () Bool)
(push 1)
(set-info :boogie-vc-id _initialize)
(assert (not
(let ((anon0_correct@@8 (=> (! (and %lbl%+2906 true) :lblpos +2906) (and
(! (or %lbl%@4652 (= (bvlshr #x00000000 #x00000007) #x00000000)) :lblneg @4652)
(=> (= (bvlshr #x00000000 #x00000007) #x00000000) (and
(! (or %lbl%@4662 (= (bvlshr (bvmul #x00000080 $unitSize) #x00000007) $unitSize)) :lblneg @4662)
(=> (= (bvlshr (bvmul #x00000080 $unitSize) #x00000007) $unitSize) (and
(! (or %lbl%@4676 (= (bvlshr (bvmul #x00000100 $unitSize) #x00000007) (bvadd $unitSize $unitSize))) :lblneg @4676)
(=> (= (bvlshr (bvmul #x00000100 $unitSize) #x00000007) (bvadd $unitSize $unitSize)) true)))))))))
(let ((PreconditionGeneratedEntry_correct@@8 (=> (! (and %lbl%+4600 true) :lblpos +4600) (=> (bvule $unitSize #x00ffffff) anon0_correct@@8))))
PreconditionGeneratedEntry_correct@@8))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+3018 () Bool)
(declare-fun %lbl%@5233 () Bool)
(declare-fun $i2 () Int)
(declare-fun $i0 () Int)
(declare-fun %lbl%@5259 () Bool)
(declare-fun $idx () Int)
(declare-fun $g1 () Int)
(declare-fun %lbl%@5285 () Bool)
(declare-fun %lbl%@5345 () Bool)
(declare-fun $a () (Array Int Int))
(declare-fun $off () Int)
(declare-fun $aBase () Int)
(declare-fun $bb () (Array Int Int))
(declare-fun $i1 () Int)
(declare-fun $g2 () Int)
(declare-fun %lbl%+4695 () Bool)
(push 1)
(set-info :boogie-vc-id _bb4Zero)
(assert (not
(let ((anon0_correct@@9 (=> (! (and %lbl%+3018 true) :lblpos +3018) (and
(! (or %lbl%@5233 (= (bvmul #x00000080 (bvlshr (B (- $i2 $i0)) #x00000007)) (B (- $i2 $i0)))) :lblneg @5233)
(=> (= (bvmul #x00000080 (bvlshr (B (- $i2 $i0)) #x00000007)) (B (- $i2 $i0))) (and
(! (or %lbl%@5259 (= (- $idx $g1) (* 4 (I (bvlshr (B (- $i2 $i0)) #x00000007))))) :lblneg @5259)
(=> (= (- $idx $g1) (* 4 (I (bvlshr (B (- $i2 $i0)) #x00000007)))) (and
(! (or %lbl%@5285 (forall ((i@@5 Int) ) (! (=> (and
(TV i@@5)
(<= $i2 i@@5)
(< i@@5 (+ $i2 128))) (= (bvlshr (B (- i@@5 $i0)) #x00000007) (bvlshr (B (- $i2 $i0)) #x00000007)))
 :qid |BitVecto.62:18|
 :skolemid |35|
 :pattern ( (TV i@@5))
))) :lblneg @5285)
(=> (forall ((i@@6 Int) ) (! (=> (and
(TV i@@6)
(<= $i2 i@@6)
(< i@@6 (+ $i2 128))) (= (bvlshr (B (- i@@6 $i0)) #x00000007) (bvlshr (B (- $i2 $i0)) #x00000007)))
 :qid |BitVecto.62:18|
 :skolemid |35|
 :pattern ( (TV i@@6))
)) (and
(! (or %lbl%@5345 ($bbvec4 $a $off $aBase (store $bb $idx 0) $i0 $i1 (+ $i2 128) $g1 $g2)) :lblneg @5345)
(=> ($bbvec4 $a $off $aBase (store $bb $idx 0) $i0 $i1 (+ $i2 128) $g1 $g2) true)))))))))))
(let ((PreconditionGeneratedEntry_correct@@9 (=> (! (and %lbl%+4695 true) :lblpos +4695) (=> (and
(forall ((i@@7 Int) ) (! (=> (and
(TV i@@7)
(<= $i1 i@@7)
(< i@@7 (+ $i2 128))) (= (select $a (+ $aBase (- i@@7 $i0))) $off))
 :qid |BitVecto.80:20|
 :skolemid |15|
 :pattern ( (TV i@@7))
))
($bbvec4 $a $off $aBase $bb $i0 $i1 $i2 $g1 $g2)) (=> (and
($Aligned (B $idx))
($Aligned (B $g1))
(= (B (- $i2 $i0)) (bvmul #x00000020 (bvsub (B $idx) (B $g1))))
(= $i1 $i0)
(=> (and
(bvule (bvlshr (B (- $i2 $i0)) #x00000007) #x01ffffff)
(= (bvmul #x00000080 (bvlshr (B (- $i2 $i0)) #x00000007)) (B (- $i2 $i0)))) (= (- $idx $g1) (* 4 (I (bvlshr (B (- $i2 $i0)) #x00000007)))))
(forall ((i@@8 Int) ) (! (=> (and
(TV i@@8)
(<= $i2 i@@8)
(< i@@8 (+ $i2 128))) (and
(bvule (B (- $i2 $i0)) (B (- i@@8 $i0)))
(bvule (B (- i@@8 $i0)) (bvadd (B (- $i2 $i0)) #x0000007f))))
 :qid |BitVecto.87:20|
 :skolemid |16|
 :pattern ( (TV i@@8))
))
(between $g1 $g2 $idx)
(= (B 0) #x00000000)) anon0_correct@@9)))))
PreconditionGeneratedEntry_correct@@9))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+3027 () Bool)
(declare-fun %lbl%@5396 () Bool)
(declare-fun $k () Int)
(declare-fun $i0@@0 () Int)
(declare-fun %lbl%+5376 () Bool)
(push 1)
(set-info :boogie-vc-id _bb4GetBit)
(assert (not
(let ((anon0_correct@@10 (=> (! (and %lbl%+3027 true) :lblpos +3027) (and
(! (or %lbl%@5396 (bvule (bvand (bvlshr (B (- $k $i0@@0)) #x00000002) #x0000001f) #x0000001f)) :lblneg @5396)
(=> (bvule (bvand (bvlshr (B (- $k $i0@@0)) #x00000002) #x0000001f) #x0000001f) true)))))
(let ((PreconditionGeneratedEntry_correct@@10 (=> (! (and %lbl%+5376 true) :lblpos +5376) anon0_correct@@10)))
PreconditionGeneratedEntry_correct@@10))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+3078 () Bool)
(declare-fun %lbl%@5716 () Bool)
(declare-fun $a@@0 () (Array Int Int))
(declare-fun $aBase@@0 () Int)
(declare-fun $k@@0 () Int)
(declare-fun $i0@@1 () Int)
(declare-fun $on () Int)
(declare-fun $off@@0 () Int)
(declare-fun $ret () (Array Int Int))
(declare-fun $i1@@0 () Int)
(declare-fun $i2@@0 () Int)
(declare-fun $g1@@0 () Int)
(declare-fun $g2@@0 () Int)
(declare-fun %lbl%@5750 () Bool)
(declare-fun $idx@@0 () Int)
(declare-fun %lbl%@5758 () Bool)
(declare-fun %lbl%+5417 () Bool)
(declare-fun $bb@@0 () (Array Int Int))
(declare-fun $bbb () Int)
(push 1)
(set-info :boogie-vc-id _bb4SetBit)
(assert (not
(let ((anon0_correct@@11 (=> (! (and %lbl%+3078 true) :lblpos +3078) (and
(! (or %lbl%@5716 ($bbvec4 (store $a@@0 (+ $aBase@@0 (- $k@@0 $i0@@1)) $on) $off@@0 $aBase@@0 $ret $i0@@1 $i1@@0 $i2@@0 $g1@@0 $g2@@0)) :lblneg @5716)
(=> ($bbvec4 (store $a@@0 (+ $aBase@@0 (- $k@@0 $i0@@1)) $on) $off@@0 $aBase@@0 $ret $i0@@1 $i1@@0 $i2@@0 $g1@@0 $g2@@0) (and
(! (or %lbl%@5750 (between $g1@@0 $g2@@0 $idx@@0)) :lblneg @5750)
(=> (between $g1@@0 $g2@@0 $idx@@0) (and
(! (or %lbl%@5758 (bvule (bvand (bvlshr (B (- $k@@0 $i0@@1)) #x00000002) #x0000001f) #x0000001f)) :lblneg @5758)
(=> (bvule (bvand (bvlshr (B (- $k@@0 $i0@@1)) #x00000002) #x0000001f) #x0000001f) true)))))))))
(let ((PreconditionGeneratedEntry_correct@@11 (=> (! (and %lbl%+5417 true) :lblpos +5417) (=> ($bbvec4 $a@@0 $off@@0 $aBase@@0 $bb@@0 $i0@@1 $i1@@0 $i2@@0 $g1@@0 $g2@@0) (=> (and
(TV $k@@0)
(word (- $k@@0 $i0@@1))
(<= $i1@@0 $k@@0)
(< $k@@0 $i2@@0)
($Aligned (B (- $k@@0 $i0@@1)))
(not (= $on $off@@0))
(= $idx@@0 (+ $g1@@0 (* 4 (I (bvlshr (B (- $k@@0 $i0@@1)) #x00000007)))))
(= (B $bbb) (bvor (B (select $bb@@0 $idx@@0)) (bvshl #x00000001 (bvand (bvlshr (B (- $k@@0 $i0@@1)) #x00000002) #x0000001f))))
(= $ret (store $bb@@0 $idx@@0 $bbb))) anon0_correct@@11)))))
PreconditionGeneratedEntry_correct@@11))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+3187 () Bool)
(declare-fun %lbl%@6314 () Bool)
(declare-fun $i2@@1 () Int)
(declare-fun $i0@@2 () Int)
(declare-fun %lbl%@6340 () Bool)
(declare-fun $idx@@1 () Int)
(declare-fun $g1@@1 () Int)
(declare-fun %lbl%@6366 () Bool)
(declare-fun %lbl%@6426 () Bool)
(declare-fun $a@@1 () (Array Int Int))
(declare-fun $aBase@@1 () Int)
(declare-fun $bb@@1 () (Array Int Int))
(declare-fun $i1@@1 () Int)
(declare-fun $g2@@1 () Int)
(declare-fun %lbl%+5779 () Bool)
(push 1)
(set-info :boogie-vc-id _bb4Zero2)
(assert (not
(let ((anon0_correct@@12 (=> (! (and %lbl%+3187 true) :lblpos +3187) (and
(! (or %lbl%@6314 (= (bvmul #x00000040 (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006)) (B (- $i2@@1 $i0@@2)))) :lblneg @6314)
(=> (= (bvmul #x00000040 (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006)) (B (- $i2@@1 $i0@@2))) (and
(! (or %lbl%@6340 (= (- $idx@@1 $g1@@1) (* 4 (I (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006))))) :lblneg @6340)
(=> (= (- $idx@@1 $g1@@1) (* 4 (I (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006)))) (and
(! (or %lbl%@6366 (forall ((i@@9 Int) ) (! (=> (and
(TV i@@9)
(<= $i2@@1 i@@9)
(< i@@9 (+ $i2@@1 64))) (= (bvlshr (B (- i@@9 $i0@@2)) #x00000006) (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006)))
 :qid |BitVecto.77:18|
 :skolemid |36|
 :pattern ( (TV i@@9))
))) :lblneg @6366)
(=> (forall ((i@@10 Int) ) (! (=> (and
(TV i@@10)
(<= $i2@@1 i@@10)
(< i@@10 (+ $i2@@1 64))) (= (bvlshr (B (- i@@10 $i0@@2)) #x00000006) (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006)))
 :qid |BitVecto.77:18|
 :skolemid |36|
 :pattern ( (TV i@@10))
)) (and
(! (or %lbl%@6426 ($bb2vec4 $a@@1 $aBase@@1 (store $bb@@1 $idx@@1 0) $i0@@2 $i1@@1 (+ $i2@@1 64) $g1@@1 $g2@@1)) :lblneg @6426)
(=> ($bb2vec4 $a@@1 $aBase@@1 (store $bb@@1 $idx@@1 0) $i0@@2 $i1@@1 (+ $i2@@1 64) $g1@@1 $g2@@1) true)))))))))))
(let ((PreconditionGeneratedEntry_correct@@12 (=> (! (and %lbl%+5779 true) :lblpos +5779) (=> (and
(forall ((i@@11 Int) ) (! (=> (and
(TV i@@11)
(<= $i1@@1 i@@11)
(< i@@11 (+ $i2@@1 64))) (= (select $a@@1 (+ $aBase@@1 (- i@@11 $i0@@2))) 0))
 :qid |BitVecto.108:20|
 :skolemid |17|
 :pattern ( (TV i@@11))
))
($bb2vec4 $a@@1 $aBase@@1 $bb@@1 $i0@@2 $i1@@1 $i2@@1 $g1@@1 $g2@@1)) (=> (and
($Aligned (B $idx@@1))
($Aligned (B $g1@@1))
(= (B (- $i2@@1 $i0@@2)) (bvmul #x00000010 (bvsub (B $idx@@1) (B $g1@@1))))
(= $i1@@1 $i0@@2)
(=> (and
(bvule (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006) #x03ffffff)
(= (bvmul #x00000040 (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006)) (B (- $i2@@1 $i0@@2)))) (= (- $idx@@1 $g1@@1) (* 4 (I (bvlshr (B (- $i2@@1 $i0@@2)) #x00000006)))))
(forall ((i@@12 Int) ) (! (=> (and
(TV i@@12)
(<= $i2@@1 i@@12)
(< i@@12 (+ $i2@@1 64))) (and
(bvule (B (- $i2@@1 $i0@@2)) (B (- i@@12 $i0@@2)))
(bvule (B (- i@@12 $i0@@2)) (bvadd (B (- $i2@@1 $i0@@2)) #x0000003f))))
 :qid |BitVecto.115:20|
 :skolemid |18|
 :pattern ( (TV i@@12))
))
(between $g1@@1 $g2@@1 $idx@@1)
(= (B 0) #x00000000)) anon0_correct@@12)))))
PreconditionGeneratedEntry_correct@@12))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+3196 () Bool)
(declare-fun %lbl%@6475 () Bool)
(declare-fun $k@@1 () Int)
(declare-fun $i0@@3 () Int)
(declare-fun %lbl%+6455 () Bool)
(push 1)
(set-info :boogie-vc-id _bb4Get2Bit)
(assert (not
(let ((anon0_correct@@13 (=> (! (and %lbl%+3196 true) :lblpos +3196) (and
(! (or %lbl%@6475 (bvule (bvand (bvlshr (B (- $k@@1 $i0@@3)) #x00000001) #x0000001f) #x0000001f)) :lblneg @6475)
(=> (bvule (bvand (bvlshr (B (- $k@@1 $i0@@3)) #x00000001) #x0000001f) #x0000001f) true)))))
(let ((PreconditionGeneratedEntry_correct@@13 (=> (! (and %lbl%+6455 true) :lblpos +6455) anon0_correct@@13)))
PreconditionGeneratedEntry_correct@@13))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+3247 () Bool)
(declare-fun %lbl%@6863 () Bool)
(declare-fun $a@@2 () (Array Int Int))
(declare-fun $aBase@@2 () Int)
(declare-fun $k@@2 () Int)
(declare-fun $i0@@4 () Int)
(declare-fun $val () Int)
(declare-fun $ret@@0 () (Array Int Int))
(declare-fun $i1@@2 () Int)
(declare-fun $i2@@2 () Int)
(declare-fun $g1@@2 () Int)
(declare-fun $g2@@2 () Int)
(declare-fun %lbl%@6895 () Bool)
(declare-fun $idx@@2 () Int)
(declare-fun %lbl%@6903 () Bool)
(declare-fun %lbl%+6496 () Bool)
(declare-fun $bb@@2 () (Array Int Int))
(declare-fun $bbb@@0 () Int)
(declare-fun $_bbb () Int)
(push 1)
(set-info :boogie-vc-id _bb4Set2Bit)
(assert (not
(let ((anon0_correct@@14 (=> (! (and %lbl%+3247 true) :lblpos +3247) (and
(! (or %lbl%@6863 ($bb2vec4 (store $a@@2 (+ $aBase@@2 (- $k@@2 $i0@@4)) $val) $aBase@@2 $ret@@0 $i0@@4 $i1@@2 $i2@@2 $g1@@2 $g2@@2)) :lblneg @6863)
(=> ($bb2vec4 (store $a@@2 (+ $aBase@@2 (- $k@@2 $i0@@4)) $val) $aBase@@2 $ret@@0 $i0@@4 $i1@@2 $i2@@2 $g1@@2 $g2@@2) (and
(! (or %lbl%@6895 (between $g1@@2 $g2@@2 $idx@@2)) :lblneg @6895)
(=> (between $g1@@2 $g2@@2 $idx@@2) (and
(! (or %lbl%@6903 (bvule (bvand (bvlshr (B (- $k@@2 $i0@@4)) #x00000001) #x0000001f) #x0000001f)) :lblneg @6903)
(=> (bvule (bvand (bvlshr (B (- $k@@2 $i0@@4)) #x00000001) #x0000001f) #x0000001f) true)))))))))
(let ((PreconditionGeneratedEntry_correct@@14 (=> (! (and %lbl%+6496 true) :lblpos +6496) (=> ($bb2vec4 $a@@2 $aBase@@2 $bb@@2 $i0@@4 $i1@@2 $i2@@2 $g1@@2 $g2@@2) (=> (and
(TV $k@@2)
(word (- $k@@2 $i0@@4))
(<= $i1@@2 $k@@2)
(< $k@@2 $i2@@2)
($Aligned (B (- $k@@2 $i0@@4)))
(= $idx@@2 (+ $g1@@2 (* 4 (I (bvlshr (B (- $k@@2 $i0@@4)) #x00000006)))))
(bvule (B $val) #x00000003)
(= (B $bbb@@0) (bvand (B (select $bb@@2 $idx@@2)) (bvnot (bvshl #x00000003 (bvand (bvlshr (B (- $k@@2 $i0@@4)) #x00000001) #x0000001f)))))
(= (B $_bbb) (bvor (B $bbb@@0) (bvshl (B $val) (bvand (bvlshr (B (- $k@@2 $i0@@4)) #x00000001) #x0000001f))))
(= $ret@@0 (store $bb@@2 $idx@@2 $_bbb))) anon0_correct@@14)))))
PreconditionGeneratedEntry_correct@@14))
))
(check-sat)
(pop 1)
(declare-fun %lbl%+3250 () Bool)
(declare-fun %lbl%@7266 () Bool)
(declare-fun %lbl%@7276 () Bool)
(declare-fun %lbl%@7286 () Bool)
(declare-fun %lbl%@7296 () Bool)
(declare-fun %lbl%@7306 () Bool)
(declare-fun %lbl%@7316 () Bool)
(declare-fun %lbl%@7326 () Bool)
(declare-fun %lbl%@7336 () Bool)
(declare-fun %lbl%@7346 () Bool)
(declare-fun %lbl%@7356 () Bool)
(declare-fun %lbl%@7366 () Bool)
(declare-fun %lbl%@7376 () Bool)
(declare-fun %lbl%@7386 () Bool)
(declare-fun %lbl%@7396 () Bool)
(declare-fun %lbl%@7406 () Bool)
(declare-fun %lbl%@7416 () Bool)
(declare-fun %lbl%@7426 () Bool)
(declare-fun %lbl%@7436 () Bool)
(declare-fun %lbl%@7446 () Bool)
(declare-fun %lbl%@7456 () Bool)
(declare-fun %lbl%@7466 () Bool)
(declare-fun %lbl%@7476 () Bool)
(declare-fun %lbl%@7486 () Bool)
(declare-fun %lbl%@7496 () Bool)
(declare-fun %lbl%@7506 () Bool)
(declare-fun %lbl%@7516 () Bool)
(declare-fun %lbl%@7526 () Bool)
(declare-fun %lbl%@7536 () Bool)
(declare-fun %lbl%@7546 () Bool)
(declare-fun %lbl%@7556 () Bool)
(declare-fun %lbl%@7566 () Bool)
(declare-fun %lbl%+6924 () Bool)
(push 1)
(set-info :boogie-vc-id _const)
(assert (not
(let ((anon0_correct@@15 (=> (! (and %lbl%+3250 true) :lblpos +3250) (and
(! (or %lbl%@7266 (= (bvsub #x00000001 #x00000001) #x00000000)) :lblneg @7266)
(=> (= (bvsub #x00000001 #x00000001) #x00000000) (and
(! (or %lbl%@7276 (= (bvadd #x00000001 #x00000001) #x00000002)) :lblneg @7276)
(=> (= (bvadd #x00000001 #x00000001) #x00000002) (and
(! (or %lbl%@7286 (= (bvadd #x00000002 #x00000001) #x00000003)) :lblneg @7286)
(=> (= (bvadd #x00000002 #x00000001) #x00000003) (and
(! (or %lbl%@7296 (= (bvadd #x00000002 #x00000002) #x00000004)) :lblneg @7296)
(=> (= (bvadd #x00000002 #x00000002) #x00000004) (and
(! (or %lbl%@7306 (= (bvadd #x00000004 #x00000001) #x00000005)) :lblneg @7306)
(=> (= (bvadd #x00000004 #x00000001) #x00000005) (and
(! (or %lbl%@7316 (= (bvadd #x00000005 #x00000001) #x00000006)) :lblneg @7316)
(=> (= (bvadd #x00000005 #x00000001) #x00000006) (and
(! (or %lbl%@7326 (= (bvadd #x00000005 #x00000002) #x00000007)) :lblneg @7326)
(=> (= (bvadd #x00000005 #x00000002) #x00000007) (and
(! (or %lbl%@7336 (= (bvmul #x00000004 #x00000004) #x00000010)) :lblneg @7336)
(=> (= (bvmul #x00000004 #x00000004) #x00000010) (and
(! (or %lbl%@7346 (= (bvadd #x00000010 #x00000010) #x00000020)) :lblneg @7346)
(=> (= (bvadd #x00000010 #x00000010) #x00000020) (and
(! (or %lbl%@7356 (= (bvsub #x00000020 #x00000001) #x0000001f)) :lblneg @7356)
(=> (= (bvsub #x00000020 #x00000001) #x0000001f) (and
(! (or %lbl%@7366 (= (bvadd #x00000020 #x00000020) #x00000040)) :lblneg @7366)
(=> (= (bvadd #x00000020 #x00000020) #x00000040) (and
(! (or %lbl%@7376 (= (bvsub #x00000040 #x00000001) #x0000003f)) :lblneg @7376)
(=> (= (bvsub #x00000040 #x00000001) #x0000003f) (and
(! (or %lbl%@7386 (= (bvmul #x00000020 #x00000004) #x00000080)) :lblneg @7386)
(=> (= (bvmul #x00000020 #x00000004) #x00000080) (and
(! (or %lbl%@7396 (= (bvsub #x00000080 #x00000001) #x0000007f)) :lblneg @7396)
(=> (= (bvsub #x00000080 #x00000001) #x0000007f) (and
(! (or %lbl%@7406 (= (bvmul #x00000010 #x00000010) #x00000100)) :lblneg @7406)
(=> (= (bvmul #x00000010 #x00000010) #x00000100) (and
(! (or %lbl%@7416 (= (bvadd #x00000100 #x00000100) #x00000200)) :lblneg @7416)
(=> (= (bvadd #x00000100 #x00000100) #x00000200) (and
(! (or %lbl%@7426 (= (bvmul #x00000040 #x00000040) #x00001000)) :lblneg @7426)
(=> (= (bvmul #x00000040 #x00000040) #x00001000) (and
(! (or %lbl%@7436 (= (bvsub #x00001000 #x00000001) #x00000fff)) :lblneg @7436)
(=> (= (bvsub #x00001000 #x00000001) #x00000fff) (and
(! (or %lbl%@7446 (= (bvmul #x00000100 #x00000100) #x00010000)) :lblneg @7446)
(=> (= (bvmul #x00000100 #x00000100) #x00010000) (and
(! (or %lbl%@7456 (= (bvsub #x00010000 #x00000001) #x0000ffff)) :lblneg @7456)
(=> (= (bvsub #x00010000 #x00000001) #x0000ffff) (and
(! (or %lbl%@7466 (= (bvmul #x00010000 #x00000020) #x00200000)) :lblneg @7466)
(=> (= (bvmul #x00010000 #x00000020) #x00200000) (and
(! (or %lbl%@7476 (= (bvsub #x00200000 #x00000001) #x001fffff)) :lblneg @7476)
(=> (= (bvsub #x00200000 #x00000001) #x001fffff) (and
(! (or %lbl%@7486 (= (bvmul #x00010000 #x00000100) #x01000000)) :lblneg @7486)
(=> (= (bvmul #x00010000 #x00000100) #x01000000) (and
(! (or %lbl%@7496 (= (bvsub #x01000000 #x00000001) #x00ffffff)) :lblneg @7496)
(=> (= (bvsub #x01000000 #x00000001) #x00ffffff) (and
(! (or %lbl%@7506 (= (bvmul #x00010000 #x00000200) #x02000000)) :lblneg @7506)
(=> (= (bvmul #x00010000 #x00000200) #x02000000) (and
(! (or %lbl%@7516 (= (bvsub #x02000000 #x00000001) #x01ffffff)) :lblneg @7516)
(=> (= (bvsub #x02000000 #x00000001) #x01ffffff) (and
(! (or %lbl%@7526 (= (bvadd #x02000000 #x02000000) #x04000000)) :lblneg @7526)
(=> (= (bvadd #x02000000 #x02000000) #x04000000) (and
(! (or %lbl%@7536 (= (bvsub #x04000000 #x00000001) #x03ffffff)) :lblneg @7536)
(=> (= (bvsub #x04000000 #x00000001) #x03ffffff) (and
(! (or %lbl%@7546 (= (bvmul #x00010000 #x0000ffff) #xffff0000)) :lblneg @7546)
(=> (= (bvmul #x00010000 #x0000ffff) #xffff0000) (and
(! (or %lbl%@7556 (= (bvadd #xffff0000 #x0000ffff) #xffffffff)) :lblneg @7556)
(=> (= (bvadd #xffff0000 #x0000ffff) #xffffffff) (and
(! (or %lbl%@7566 (= (bvsub #xffffffff #x00000003) #xfffffffc)) :lblneg @7566)
(=> (= (bvsub #xffffffff #x00000003) #xfffffffc) true)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
(let ((PreconditionGeneratedEntry_correct@@15 (=> (! (and %lbl%+6924 true) :lblpos +6924) anon0_correct@@15)))
PreconditionGeneratedEntry_correct@@15))
))
(check-sat)
(pop 1)
