import "std.ink"

u64 main = {
	u64 var i = 0;
	while i < 10 {
		print "loop\n";
		i = i + 1;
	};
	return 0;
};
