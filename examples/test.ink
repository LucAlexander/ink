import "io.ink"

u64 main = {
	Arena pool = arena_init 512 ARENA_STATIC;
	u8^ buffer = (&pool) ## 10;
	u64 stack_allocated = 64;
	u64^ arena_allocated = stack_allocated =:> &pool;
	[u64] fat_allocated = stack_allocated =:: &pool;
	[u64] moved = fat_allocated =:>> &pool;

	String left = string_init (&pool) "first ";
	String right = zero " second\n" &pool;
	
	u64 numeric = 5;

	print $ left +% numeric ++ right;
	return 0;
};
