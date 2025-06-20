import "std.ink"

u64 -> u64 -> u64 sum = \x y : {
	print "added\n";
	return x + y;
};

(u64 -> u64) -> u64 -> u64
mutator = \mutation value:{
	print "mutated\n";
	return mutation value;
};

u64 main = {
	u64 -> u64 inc = sum 1;
	u64 seven = mutator inc 6;	
	return 0;
};
