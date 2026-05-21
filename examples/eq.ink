import "std.ink"

type Bool = enum {true, false};

typeclass Eq E {
	E -> E -> u64 ===;
}

type Nat = u64;

Nat implements Eq {
	Nat -> Nat -> u64
	=== = \x y: (x as u64) == (y as u64);
}

u64 main = {
	Nat x = 6;
	Nat y = 6;
	if x === y {
		print "theyre equal";
		return 0;
	};
	print "not equal";
	return 0;
};
