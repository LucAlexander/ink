
alias string = [i8];

constant null = 0;

external {
	u8^ -> u8^ -> u64 -> u8 memcpy;
	u8^ -> u8 -> u64 -> u8 memset;
	u64 -> u8^ -> u64 -> u64 write;
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
alloc = \size:
	malloc size;

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

typeclass Stackable S {
	S T -> T -> S T push;
	S T -> T pop;
}

type buffer T  = struct {
	arena^ mem;
	[T var] data;
	u64 var count;
};

buffer implements Stackable {
	buffer T -> T -> buffer T
	push = \list elem:{
		u64 var new_capacity = list.data.len;
		if list.data.len == (list.count) {
			new_capacity = list.data.len * 2;
		};
		[T var] new_buffer = [
			list.data.ptr,
			new_capacity
		] =:>> (list.mem).val;
		memcpy (new_buffer.ptr) (list.data.ptr) (list.data.len * sizeof T);
		new_buffer.ptr[list.count] = elem;
		return {list.mem, new_buffer, list.count + 1};
	};
	
	buffer T -> T
	pop = \list: {
		list.count = list.count - 1;
		return list.data.ptr[list.count];
	};
}

typeclass Formattable F {
	arena^ -> F -> string format;
}

alias uword = u64;
alias word = i64;
alias ubyte = u8;
alias byte = i8;

uword implements Formattable {
	arena^ -> uword -> string
	format = \pool value:{
		u64 var walk = value;
		walk = value;
		i8 var^ result = (pool # 0) as i8^;
		u64 var index = 0;
		while walk > 0 {
			pool # 1;
			u64 digit = walk % 10;
			i8 zero = '0';
			result[index] = digit + zero;
			index = index + 1;
			walk = walk / 10;
		};
		string converted = [result, index + 1];
		return converted;
	};
}
