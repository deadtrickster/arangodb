# Corpus quarantine ledger

One line per seed that is NOT in the corpus directory, keyed by sha256 so the
entry survives merges and re-extraction (corpus filenames are generated).
Reconciliation is exact: every file on disk has no line here, every line here
has no file on disk. The pre-slice hang gate asserts the two agree.

    <sha256>  <finding>  <reason>  <where the bytes live>  <commit that withdraws this line>

4ed3faf468082eac4eda4924e4673874e50c30f816c05c73246fd56cf78163d0  0012  hang  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input.bin  (pending upstream drain-contract fix)
9bc17d8b0544f6d99531870b7852303e6b3be467defb3ce18729d9d18e59f313  0012  hang  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input-2-length-desync.bin  (pending upstream drain-contract fix)
de9f15651ec4737f5456d8a53f5a7b46fb4a08a1676e79ee9802046795984d13  0012  hang  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input-3-vvv.bin  (third witness, found by the block-fragmenting harness: 3-byte "VVV", type flipped to kRecyclableFirstType=6 by mutation 0x56%5=1, same first_record_read_ && !recycled_ guard, frame lands on the header-parse at :480 because that is where the loop's attribution sits. Same class, same fix.)
c905a1f5aa74941628bb25a2182177783dc3a6a743ea5245f7b5e2b45087c62b  0012  hang  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input-4-typeflip2.bin  (fourth witness, steered campaign: 34-byte type-flip, same guard)
ba6a79187514d706ca7ee368b5166f251674d5c8c3abe3188855461660d29749  0012  hang  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input-5-lengthlie2.bin  (fifth witness, steered campaign: 83-byte length-lie desync, same guard)
c59dc4e44ff99288156d4dff2168f6ac7ddee6b1fc7ccc0754656ffaa6d351ea  0006  unfixed  fuzz/findings/2025-11-06-stringutils-rtrim-strlen/input-2-plus1.bin  (second witness, found by the number-converter rebuild; rTrim strlen OOB. Withdrawal = the arangodb commit fixing rTrim's ctor — lib/Basics, not the velocypack submodule)

Both seeds re-enter the corpus in the same commit as the submodule bump that
carries the fix, at which point their lines are withdrawn naming that commit.
Restore procedure (run before any campaign): for each line, execute the seed
once under -timeout=10; if it no longer hangs, move the bytes back and delete
the line; if it still does, the fix has not landed - leave it and say so.
