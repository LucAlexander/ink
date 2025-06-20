<p align="center">
    <img src="https://github.com/LucAlexander/ink/blob/master/logo.png?raw=true" alt="logo"/>
</p>
 
# INK
Ink is a heavily WIP language project. I am writing this entirely from my own head without consulting any theory on compilation strategies or literature on compiling specific features. This is largely a learning exercise, and a way for me to get much better at programming, so I dont want to know any solutions beforehand. I entirely intend to make this language my main personal project language, and to continuously improve it as I use it.

# Current tasks
* C code generation pass
* Better error reporting system

# Working Examples

```haskell

import "std.ink"

u64 main = print "Hello world\n";

```

Simple arena type
```haskell

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

```

Parametric types
```haskell

type Maybe T = struct {
	enum {Just, Nothing} tag;
	T val;
};

```

Type classes
```haskell

typeclass Allocator A {
	T -> A -> Maybe (T^) =:>;
	[T] -> A -> Maybe [T] =:>>;
	A -> u64 -> u8^ #;
}

arena implements Allocator {
	T -> arena -> Maybe (T^)
	=:> = \val a:{
		if a.ptr + (sizeof T) < (a.size) {
			u64 pos = a.ptr;
			a.ptr = a.ptr + (sizeof T);
			return {Just, &(a.buffer[pos])};
		};
		return {Nothing};
	};

	[T] -> arena -> Maybe [T]
	=:>> = \val a:{
		[T] pooled = [
			(a # ((sizeof T) * (val.len))) as (T^),
			val.len
		];
		memcpy (pooled.ptr as u8^) (val.ptr as u8^) (pooled.len * (sizeof T));
		return {Just, pooled};
	};

	arena -> u64 -> u8^
	# = \a size:{
		if a.ptr + size < (a.size) {
			u64 pos = a.ptr;
			a.ptr = a.ptr + size;
			return &(a.buffer[pos]);
		};
		return null as u8^;
	};
}

```
