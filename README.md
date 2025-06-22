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

```

Copying closures
```

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

```

Simple stack buffer
```

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

```
