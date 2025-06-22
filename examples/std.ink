
alias string = [i8];

constant null = 0;

external {
	u8^ -> u8^ -> u64 -> u8 memcpy;
	u8^ -> u8 -> u64 -> u8 memset;
	u64 -> u8^ -> u64 -> u64 write;
	u8^ -> u64 -> u64 -> u64 -> u64 -> u64 -> u8^ mmap;
	u64 -> u8^ malloc;
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
	return malloc size;
	//return mmap (null as u8^) size (1 ^| 2) (2 ^| 32) 0 0;
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
	T -> A -> Maybe (T^) =:>;
	[T] -> A -> Maybe [T] =:>>;
	A -> u64 -> u8^ #;
}

arena implements Allocator {
	T -> arena^ -> Maybe (T^)
	=:> = \val a:{
		if a.ptr + (sizeof T) < (a.size) {
			u64 pos = a.ptr;
			a.ptr = a.ptr + (sizeof T);
			T^ source = &val;
			memcpy (&(a.buffer[pos])) (source as u8^) (sizeof T);
			return {Just, &(a.buffer[pos])};
		};
		return {Nothing};
	};

	[T] -> arena^ -> Maybe [T]
	=:>> = \val a:{
		[T] pooled = [
			(a # ((sizeof T) * (val.len))) as (T^),
			val.len
		];
		memcpy (pooled.ptr as u8^) (val.ptr as u8^) (pooled.len * (sizeof T));
		return {Just, pooled};
	};

	arena^ -> u64 -> u8^
	# = \a size:{
		if a.ptr + size < (a.size) {
			u64 pos = a.ptr;
			a.ptr = a.ptr + size;
			return &(a.buffer[pos]);
		};
		return null as u8^;
	};
}

arena^ -> [T] -> [T]
copy = \pool closure:{
	u64 size_point = (closure.ptr as u64) + (closure.len) - (sizeof u64);
	u64 offset = 0;
	memcpy ((&offset) as u8^)
	       (size_point as u8^)
	       (sizeof u64);
	u64 closure_start = size_point - (offset + sizeof u8^);
	Maybe ([T] var) moved = [
		(closure_start as T^),
		offset + (2 * sizeof u8^)
	] =:>> pool;
	u64 original = (closure.ptr as u64) - closure_start;
	u64 new_pos = (moved.val.ptr as u64) + original;
	return [
		(new_pos as T^),
		moved.val.len
	];
};
