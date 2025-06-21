import "std.ink"


arena^ -> u64 ~> u64 -> u64 effectful = \a x: {
	u64 -> u64 f = \y: x + y;
	print "side effect\n";
	return (((f =:>> a).val) =:> a).val;
};

u64 main = {
	arena pool = arena_init 100;
	u64 -> u64 f = ^(effectful (&pool) 1);
	u64 three = f 2;
	print "After effect\n";
	return 0;
};
