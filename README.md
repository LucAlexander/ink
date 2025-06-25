<p align="center">
    <img src="https://github.com/LucAlexander/ink/blob/master/logo.png?raw=true" alt="logo"/>
</p>
 
# INK
Ink is a heavily WIP language project. I am writing this entirely from my own head without consulting any theory on compilation strategies or literature on compiling specific features. This is largely a learning exercise, and a way for me to get much better at programming, so I dont want to know any solutions beforehand. I entirely intend to make this language my main personal project language, and to continuously improve it as I use it.

# Current tasks
* C code generation pass
*   for loops dont exist
*   we include more functions in the binary than are necessarily called
*   polymorphic functions dont successfully type check on literals
*   dependency resolution is missing for structure declaration order
*   list literals dont generate correctly 
* Better error reporting system

# Hello world

```haskell

import "io.ink"

u64 main = print "Hello world\n";

```

# More contrived example: formatted printing


test.ink:
```haskell
import "io.ink"

u64 main = {
    Arena pool = arena_init 512 ARENA_STATIC;
    String left = string_init (&pool) "first ";
    String right = string_init (&pool) " second";
    u64 numeric = 5;
    return printf $ left +% numeric ++ right;
};

```

io.ink:
```haskell

import "string.ink"

String -> u64
printf = \msg:
	write 1 ((msg.data.ptr) as (u8^)) (msg.data.len);

[i8] -> u64
print = \msg:
	write 1 ((msg.ptr) as (u8^)) (msg.len);

typeclass Formattable F {
	String -> F -> String +%;
}

uword implements Formattable {
	String -> uword -> String
	+% = \left value:{
		u64 var walk = value;
		i8 var^ result = (left.mem ## 0) as i8^;
		u64 var index = 0;
		while walk > 0 {
			(left.mem) ## 1;
			u64 digit = walk % 10;
			i8 zero = '0';
			result[index] = digit + zero;
			index = index + 1;
			walk = walk / 10;
		};
		String converted = string_init (left.mem) [result, index + 1];
		return left ++ converted;
	};
}

```

string.ink:
```haskell

import "allocators.ink"

type String = struct {
	Arena^ mem;
	[i8] data;
};

Arena^ -> [i8] -> String
string_init = \pool data: {pool, data =:>> pool};

typeclass MonoidAlloc M {
	(Allocator A) => T -> A^ -> M zero;
	M -> M -> M ++;
}

String implements MonoidAlloc {
	[i8] -> Arena^ -> String
	zero = \data pool: string_init pool data;

	String -> String -> String
	++ = \left right:{
		u64 new_size = left.data.len + (right.data.len);
		i8^ new = (left.mem ## new_size) as i8^;
		[i8] data = [new, new_size];
		u64 offset = (new as u64) + (left.data.len);
		memcpy (data.ptr as u8^) (left.data.ptr as u8^) (left.data.len);
		memcpy (offset as u8^) (right.data.ptr as u8^) (right.data.len);
		return zero data (left.mem);
	};
}

```

allocators.ink:
```haskell

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

```
