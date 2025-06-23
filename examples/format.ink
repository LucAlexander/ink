import "std.ink"

u64 main = {
	arena pool = arena_init 100;
	u64 x = 5;
	print (format (&pool) x);
	return print "\n";
};
