import "std/io.ink"
import "std/ffi.ink"

u64 main = {
	i32 var i = 0;
	for ; i < 10; i = i + 1 {
		print "hello\n";
	};

	for i32 var k = 0;k<10;k = k + 1 {
		print "world\n";
	};
	return 0;
};
