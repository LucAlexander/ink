import "std.ink"

u64 -> u64 -> u64 sum = \x y : {
	print "added\n";
	return x + y;
};

u64 main = {
	u64 -> u64 inc = sum 1;
	u64 three = inc 2;
	return three;
};
