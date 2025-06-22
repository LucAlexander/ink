import "std.ink"

u64 main = {
	arena pool = arena_init 100;
	u64 -> u64 -> u64 multiply = \x y: x*y;
	u64 -> u64 double = multiply 2;
	u64 -> u64 alternate = copy (&pool) double;
	u64 x = alternate 5;
	return print "Copied Closure\n";
};
