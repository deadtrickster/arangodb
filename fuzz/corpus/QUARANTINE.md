# Corpus quarantine ledger

One line per seed that is NOT in the corpus directory, keyed by sha256 so the
entry survives merges and re-extraction (corpus filenames are generated).
Reconciliation is exact: every file on disk has no line here, every line here
has no file on disk. The pre-slice hang gate asserts the two agree.

    <sha256>  <finding>  <reason>  <where the bytes live>  <commit that withdraws this line>

4ed3faf468082eac4eda4924e4673874e50c30f816c05c73246fd56cf78163d0  0012  hang  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input.bin  (pending upstream drain-contract fix)
9bc17d8b0544f6d99531870b7852303e6b3be467defb3ce18729d9d18e59f313  0012  hang  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input-2-length-desync.bin  (pending upstream drain-contract fix)
c59dc4e44ff99288156d4dff2168f6ac7ddee6b1fc7ccc0754656ffaa6d351ea  0006  unfixed  fuzz/findings/2025-11-06-stringutils-rtrim-strlen/input-2-plus1.bin  (second witness, found by the number-converter rebuild; rTrim strlen OOB. Withdrawal = the arangodb commit fixing rTrim's ctor — lib/Basics, not the velocypack submodule)

Both seeds re-enter the corpus in the same commit as the submodule bump that
carries the fix, at which point their lines are withdrawn naming that commit.
Restore procedure (run before any campaign): for each line, execute the seed
once under -timeout=10; if it no longer hangs, move the bytes back and delete
the line; if it still does, the fix has not landed - leave it and say so.
