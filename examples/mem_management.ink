import "std.ink"

u64 main = {
	arena pool = arena_init 1000;
	return print ("allocated\n" as string);
};
