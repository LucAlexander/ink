import "std.ink"

u64 main = {
	arena pool = arena_init 128;
	string name = "Richard\n";
	Maybe string pooled = name =:>> pool;
	print (pooled.val);
	return 0;
};
