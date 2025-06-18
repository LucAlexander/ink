
alias string = [i8];

external {
	u8^ -> u8^ -> u64 -> u8 memcpy;
	u8^ -> u8 -> u64 -> u8 memset;
	u64 -> u8^ -> u64 -> u64 write;
	u8^ -> u64 -> u64 -> u64 -> u64 -> u64 -> u8^ mmap;
}

T -> T -> T + = \x y: 0;
T -> T -> T - = \x y: 0;
T -> T -> T * = \x y: 0;
T -> T -> T / = \x y: 0;
T -> T -> T % = \x y: 0;
T -> T -> T && = \x y: 0;
T -> T -> T || = \x y: 0;
T -> T -> T ^| = \x y: 0;
T -> T -> T ^& = \x y: 0;
T -> T -> T ^^ = \x y: 0;
T -> T -> T < = \x y: 0;
T -> T -> T > = \x y: 0;
T -> T -> T <= = \x y: 0;
T -> T -> T >= = \x y: 0;
T -> T -> T == = \x y: 0;
T -> T -> T != = \x y: 0;
T -> T ! = \x: 0;
T -> T ^~ = \x: 0;

(A -> B) -> (C -> A) -> C -> B
compose = \f g x:
	f (g x);

string -> u64
print = \msg:
	write 1 ((msg.ptr) as (u8^)) (msg.len);

u64 -> u8^
alloc = \size:{
	u8 null = 0;
	return mmap (null as u8^) size (1 ^| 2) (2 ^| 32) 0 0;
};

type Maybe T = struct {
	enum {Just, Nothing} tag;
	T val;
};

type arena = struct {
	u8 var^ buffer;
	u64 var size;
	u64 var ptr;
};

u64 -> arena
arena_init = \size:{
	arena a = {
		buffer = alloc size,
		size = size,
		ptr = 0
	};
	return a;
};

typeclass Allocator A {
	A -> T -> Maybe T^ =:>;
	A -> T^ -> Maybe T^ =:>>;
	A -> u64 -> Maybe u8^ #;
}

arena implements Allocator {
	arena -> T -> Maybe T^
	=:> = \a val:{
		if a.ptr + (sizeof T) < a.size {
			u64 pos = a.ptr;
			a.ptr = a.ptr + (sizeof T);
			return {Just, &(a.buffer[pos])};
		};
		return {Nothing};
	};

	arena -> T^ -> Maybe T^
	=:>> = \a val:{
		T^ pooled = a # sizeof(T);
		^T = ^val;
		return {Just, pooled};
	};

	A -> u64 -> Maybe u8^
	# = \a size:{
		u64 pos = a.ptr;
		a.ptr = a.ptr + size;
		return {Just, &(a.buffer[pos])};
	};
}
