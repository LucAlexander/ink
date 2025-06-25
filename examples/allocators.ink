import "builtin.ink"

u64 -> u8^
alloc = \size: malloc size;

typeclass Allocator A {
	T -> A^ -> T^ =:>;
	A^ -> T -> T^ <:=;
	T -> A^ -> [T] =::;
	A^ -> T -> [T] ::=;
	A^ -> u64 -> u8^ ##;
	[T] -> A^ -> [T] =:>>;
	A^ -> [T] -> [T] <<:=;
}

alias ARENA_TAG = enum {
	ARENA_STATIC, ARENA_DYNAMIC
};

type Arena = struct {
	Arena^ next;
	u8^ buffer;
	u64 var ptr;
	u64 capacity;
	ARENA_TAG tag;
};

u64 -> ARENA_TAG -> Arena
arena_init = \size tag: {(null as Arena^), alloc size, 0, size, tag};

Arena implements Allocator {
	T -> Arena^ -> T^
	=:> = \val pool: {
		if pool.ptr + (sizeof T) >= (pool.capacity){
			return null as T^;
		};
		u64 pos = pool.ptr;
		pool.ptr = pool.ptr + (sizeof T);
		T^ source = &val;
		memcpy (&(pool.buffer[pos])) (source as u8^) (sizeof T);
		return &(pool.buffer[pos]);
	};

	T -> Arena^ -> [T]
	=:: = \val pool: {
		if pool.ptr + (sizeof T) >= (pool.capacity){
			return [(null as T^), 0];
		};
		u64 pos = pool.ptr;
		pool.ptr = pool.ptr + (sizeof T);
		T^ source = &val;
		memcpy (&(pool.buffer[pos])) (source as u8^) (sizeof T);
		return [&(pool.buffer[pos]), 1];
	};

	Arena^ -> u64 -> u8^
	## = \pool size:{
		if pool.ptr + size >= (pool.capacity) {
			return null as u8^;
		};
		u64 pos = pool.ptr;
		pool.ptr = pool.ptr + size;
		return &(pool.buffer[pos]);
	};

	[T] -> Arena^ -> [T]
	=:>> = \val pool: {
		[T] pooled = [
			(pool ## ((sizeof T) * (val.len))) as (T^),
			val.len
		];
		memcpy (pooled.ptr as u8^) (val.ptr as u8^) (pooled.len * (sizeof T));
		return pooled;
	};

	Arena^ -> T -> T^
	<:= = \pool val: val =:> pool;

	Arena^ -> T -> [T]
	::= = \pool val: val =:: pool;

	Arena^ -> [T] -> [T]
	<<:= = \pool val: val =:>> pool;
}
