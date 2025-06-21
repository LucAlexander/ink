import "std.ink"

u64 main = {
	arena pool = arena_init 1000;
	string msg = "allocated\n";
	Maybe (string^) pooled = msg =:> &pool;
	return print ^(pooled.val);
};
