import "std.ink"

u64 main = {
	arena mem = arena_init 100;
	buffer u8 stack = {&mem, [(&mem) # (sizeof u8), 1], 1};
	buffer u8 new_stack = push stack 1;
	u8 top_value = pop new_stack;
	u8 old_value = pop stack;
	print "pushed and popped\n";
	return 0;
};
