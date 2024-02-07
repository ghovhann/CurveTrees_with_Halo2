; ModuleID = 'probe4.639ca74b1e79e97f-cgu.0'
source_filename = "probe4.639ca74b1e79e97f-cgu.0"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-macosx11.0.0"

@alloc_ce3a9e44703fb88c53c5f51d5cf3d2ea = private unnamed_addr constant <{ [75 x i8] }> <{ [75 x i8] c"/rustc/2c1b65ee1431f8d3fe2142e821eb13c623bbf8a0/library/core/src/num/mod.rs" }>, align 1
@alloc_617787ce67a9b2d78d736ab097a407aa = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_ce3a9e44703fb88c53c5f51d5cf3d2ea, [16 x i8] c"K\00\00\00\00\00\00\00y\04\00\00\05\00\00\00" }>, align 8
@str.0 = internal constant [25 x i8] c"attempt to divide by zero"

; probe4::probe
; Function Attrs: uwtable
define void @_ZN6probe45probe17h242df252da451822E() unnamed_addr #0 {
start:
  %0 = call i1 @llvm.expect.i1(i1 false, i1 false)
  br i1 %0, label %panic.i, label %"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17h2c50c9246fe93f94E.exit"

panic.i:                                          ; preds = %start
; call core::panicking::panic
  call void @_ZN4core9panicking5panic17hc153ec548d4ea688E(ptr align 1 @str.0, i64 25, ptr align 8 @alloc_617787ce67a9b2d78d736ab097a407aa) #3
  unreachable

"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17h2c50c9246fe93f94E.exit": ; preds = %start
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(none)
declare i1 @llvm.expect.i1(i1, i1) #1

; core::panicking::panic
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking5panic17hc153ec548d4ea688E(ptr align 1, i64, ptr align 8) unnamed_addr #2

attributes #0 = { uwtable "frame-pointer"="non-leaf" "target-cpu"="apple-m1" }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(none) }
attributes #2 = { cold noinline noreturn uwtable "frame-pointer"="non-leaf" "target-cpu"="apple-m1" }
attributes #3 = { noreturn }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.76.0-nightly (2c1b65ee1 2023-11-11)"}
