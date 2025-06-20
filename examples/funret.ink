import "std.ink"

arena -> u64 -> u64 -> u64 incrementor = \a x: {
	u64 -> u64 f = (\y: x + y);
	print "side effect\n";
	return (f =:>> a).val;
};

u64 main = {
	arena pool = arena_init 100;
	u64 -> u64 inc = incrementor pool 1;
	print "After first application\n";
	u64 three = inc 2;
	return 0;
};
