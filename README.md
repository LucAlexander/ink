<p align="center">
    <img src="https://github.com/LucAlexander/ink/blob/master/logo.png?raw=true" alt="logo"/>
</p>
 
# INK
Ink is a heavily WIP language project. I am writing this entirely from my own head without consulting any theory on compilation strategies or literature on compiling specific features. This is largely a learning exercise, and a way for me to get much better at programming, so I dont want to know any solutions beforehand. I entirely intend to make this language my main personal project language, and to continuously improve it as I use it.

# Current tasks
* Better error reporting system
* Some bugs

# Documentation

This guide is not specifically targeted toward new programmers. You may be expected to know a thing or two, but I do my best at explaining things in a way a new programmer could understand it. Good luck.

# Brief Tour
## Basics

An Ink program consists of a list of term, constant, type, and type alias definitions. The order of these definitions is arbitrary, as Ink will resolve type dependencies.

A term requires a type, a name, and a value.

```haskell

u64 x = 5;

```

A type or alias require a name and a type.

```haskell

type byte = i8;

alias cstr = i8^;

```

Constants require a name and a value.

```haskell

constant PI = 3.14;

```

All ink programs require a main term of type `u64`.

```haskell
import "std/io.ink"

u64 main = print "Hello World!\n";

```

Global terms are computed at reference, local terms or closures are computed at definition.

## Comments
``` haskell

// gives you a single line comment

/*
	gives you a multi line comment
*/

```

## Types

Types may be one of a limited set of primitives.
* Unsigned integers: `u64, u32, u16, u8`
* Signed integers: `i64, i32, i16, i8`
* Single and double precision floating point numbers: `f32, f64`

Types may be pointers to other types, a pointer to a type `A` looks like `A^`. Ink supports native fat pointers, containing a pointer and a length, a fat pointer to `A` looks like `[A]`.

Types may also represent functions, a function taking an argument `A` and returning a type `B` looks like `A -> B`. A function to a pointer type like `A -> B^` may be written with the shorthand `A ~> B`. All function types are left associative.

The last three compound types are structure types, and accord precisely to their C language equivalents.
`struct` is a product type.
```haskell

type pair = struct {
	u64 a;
	u64 b;
};

```

Instances of structs can be created and accessed like
```haskell

u64 main = {
	pair x = {3, 4};
	pair y = {b=3, a=4};
	pair z = {a=3, 4};
	u64 position_x = x.a;
	u64 position_y = y.b;
	return position_x;
};

```

Fat pointers are structures internally, and their members may be accessed as `ptr` and `len`. The length is stored as a `u64`.

* `union` is the data component of a sum type.
```haskell

type entity = union {
	struct {
		f32 x;
		f32 y;
		u8 health;
	} player;
	struct 
		f32 x;
		f32 y;
		entity^ target;
	} enemy;
};

```

Unions may be accessed just like structures.

Unions are not tagged by default, but may be informally tagged with enumerators. 

* `enum` is a primitive enumerator. Its enumerated values are treated as literals, and its internal values begin at 0, and increment linearly unless explicitly defined.
```haskell

type entity_type = enum {
	PLAYER_ENTITY = 1,
	ENEMY_ENTITY  // continues incrementing, its value is 2
};

alias Bool = enum {
	false, // 0
	true   // 1
};

u64 main = {
	Bool happy = true;
	Bool tired = false;
	return 0;
};

```

All types are infinitely composable. Keep in mind that alias definitions cannot be recursive at all (even pointer recursive), and structure/union types are not allowed to be structure or union recursive. 

You can cast between really any two types with the `as` keyword.
``` haskell
u64 x = 0;
u8 y = x as u64;

```

You can get the size of any type interface with the `sizeof` keyword.

```haskell

u64 x = sizeof struct {u64 a; u64 b;};

```

## Mutation
All types are immutable by default, but can be marked mutable with the `var` keyword. Mutation may only happen explicitly, no implicit mutation function exist such as `+= -= ++ --`. Mutation can of course only be done on terms marked with `var` . Global terms are computed on reference and can not be mutated, local terms are computed at declaration and can be mutated. Mutation is performed with the `=` special form.
```haskell

u64 main = {
	f32 var x = 0;
	x = 1;
	return x;
};

```

## Values
### Primitives
``` haskell

u8 a = 0;
i8 b = -1;
f32 c = 9;
f32 d = 3.14;
f32 e = -3e10;
f64 f = 3.8e-9;

```

### Expressions
More complicated expressions exist for each of the compound types.
#### Constructors
We have already seen structure constructors, but there is special syntax for unions
```haskell

type entity = struct {
	enum {PLAYER, ENEMY} tag;
	union {
		struct {
			f32 x;
			f32 y;
			u8 hp;
		} player;
		struct {
			f32 x;
			f32 y;
			entity^ target;
		} enemy;
	};
};

u64 main = {
	struct {u64 a; u64 b;} pair = {a=0, b=1};
	struct {u64 a; u64 b;} pair2 = {0, 1};
	struct {u64 a; u64 b;} pair3 = {a=0, 1};
	struct {u64 a; u64 b;} pair4 = {5}; // sets a
	struct {u64 a; u64 b;} pair5 = {b=0, a=1};

	entity bob    = {PLAYER, player = {0, 0, 10}   };
	entity zombie = {ENEMY,  enemy  = {0, 0, &bob} };
	
	return 0;
};

```

#### Pointers
Pointers and fat pointers may be assigned to list or string literals.
```haskell

u64 main = {
	i8^ cstring = "Hello world\n";
	[i8] fat_cstring = "Hello world\n";
	
	u8^ x = [1, 2, 3];
	
	[u8] y = [ // fat pointer to a buffer of length 3
		[0], 3
	]; 
	
	return 0;
};

```

Pointers may also be set to the address of another term.
```haskell

u64 main = {
	u32 x = 0;
	u32^ ptr = &x;
	[u32] = [&x, 1];
	return ^ptr;
};

```

#### Blocks
Blocks are multi-line expressions. Since all expressions in Ink are `;` terminated, block expressions simply require sequential expressions. The final expression in a block must be a `return` expression, which designates the value of the block expression if it were to be computed. All expressions in a block may use all previous term definitions in the block to create compound expressions. 
```haskell

u64 main = {
	u64 x = 0;
	u64 y = {
		u64 f = x + 6;
		return f
	};
	return y;
};

```

#### Conditionals
##### if / else
If/else cna ben used as both a statement and an expression, if used as an expression it must have an else and the resulting types between the two branches must match, otherwise they can have any type and dont have to return. If used as a statement, returning will return from the outer block.

```haskell

u64 main = {
	u64 x = if 1 { return 8; } else { return 9; };
	if x {
		return 1;
	};
	return 0;
};

```

##### while
While is just repeated if, you cannot use it as an expression and it doesn't get an else.

```haskell
import "std/io.ink"
import "std/ffi.ink"

u64 main = {
	u64 var i = 0;
	while i < 10 {
		print "Hello\n";
	};
	return i;
};

```

##### for
For is a structured while loop, it takes an initial clause, a condition to check, and a mutation clause that runs at the end of each iteration.

```haskell
import "std/io.ink"
import "std/ffi.ink"

u64 main = {
    for i32 var i = 0; i<10 ; i=i+1 {
        print "hi\n";
    };
    return 0;
};
```

##### match
This is a pattern matching statement.
```haskell

type Maybe = struct {
	enum {Just, Nothing} tag;
	i32 val;
};

Maybe -> u8 f = \m:
	match m {
		(Just 1): 0;
		(Just x): x as u8;
		result@(Nothing): result.val;
		_: 1;
	};

```

Patterns follow the following composable rules:
* `binding@inner_pattern` names a pattern and continues to match against it
* `[fat_ptr_ptr fat_ptr_len]`
* `_` matches anything
* `(x 6 5)` matches a structure with the first member bound to x for the resulting expression, and the next two members checked against 6 and 5

#### Lambdas
All functions in Ink are values, the canonical value of a term with a function type, is a lambda expression. Lambdas have arguments and a resulting expression.
```haskell

u64 -> u64 incrememnt = \x: x + 1;

u64 -> u64 -> u64 sum = \a b: a + b;

u64 -> u64 -> u64
greater = \left right: {
	u64 x = left > right;
	return left > right;
};

```

Lambda args are patterns, and will be matched before the function starts.
You may consequently have alternate matching cases for lambda args:
```haskell

Maybe -> u8 f = \(Just x): x as u8;
              | \(Nothing): 0;
              | \_: 0;

```

#### Application
To apply a function, we simple place its argument(s) after its name. Symbol named functions are allowed to be infix but may also be prefixed.

```haskell

u64 -> u64 -> u64 sum = \a b: a + b;

u64 main = {
	u64 x = sum 4 5;
	u64 y = (- 10 x);
	return x + y;
};

```

You do not need to apply function fully, they may instead be partially applied.
```haskell

u64 -> u64 -> u64
sum = \a b: a + b;

u64 main = {
	u64 -> u64 add_four = sum 4;
	u64 y = add_four 5;
	return y;
};

```

Just like in Haskell, you can use `$` to turn the default left associative function application into a right associative one.

```haskell

// these two are equivalent
f $ x y z;
(f ((x y) z));

```

Composition has a syntactic shorthand as well.

``` haskell

// these two are equivalent
f . g . h a;
(f (g (h a)));

```

The body of a term will not be evaluated by an application to a reference to that term until that term's type is reduced to a non function.

It should be mentioned that lambdas, structure expressions, blocks, and any other type of expression, can be used entirely anonymously as long as the type is inferrable from its context.

## Memory
Memory stored in a memory space other than the managed stack region, must be managed explicitly. This follows the semantics of languages like C, mostly this means you just shouldn't dangle stack pointers to stack allocated terms, but the way closures are represented in Ink requires special attention to the memory of the program.

Closures in Ink are designed to ensure the programmer still has control over the way their memory is being allocated, and the way its being accessed. You can safely use closures knowing predictably how their metadata will be accessed and stored. This means you can reason about functional programs using closures without having to rely on the slowdowns of default heap allocation, odd memory access patterns causing cache misses, or garbage collection overhead.

All you need to know is that closures are secretly fat pointers to stack allocated packed structures. Since they are stack allocated, this means you can pass closures as arguments to terms without issue.
```haskell

u64 -> u64 -> u64 sum = \x y : {
	return x + y;
};

(u64 -> u64) -> u64 -> u64
mutator = \mutation value:{
	return mutation value;
};

u64 main = {
	u64 -> u64 inc = sum 1;
	u64 seven = mutator inc 6;	
	return 0;
};

```

Returning them however, requires you move their memory from the stack to an alternative memory region with a custom allocator. The tiny standard library which does exist for Ink includes an arena allocator, which implements the `Allocator` typeclass.

``` haskell
import "std/io.ink"

arena^ -> u64 -> u64 -> u64 incrementor = \a x: {
	u64 -> u64 f = (\y: x + y);
	print "side effect\n";
	return f =:>> a; // moves f into a
};

u64 main = {
	arena pool = arena_init 100;
	u64 -> u64 inc = incrementor (&pool) 1;
	print "After first application\n";
	u64 three = inc 2;
	return 0;
};
```

Note here that the output order is 
```
After first application
side effect
```

This is because the applied reference to incrementor has not resolved to a non function type, so the procedure does not evaluate until that type is reduced at the operation
```haskell
u64 three = inc 2;
```

If you want explicit currying, that is, returning a closure while running the procedure it came from, you can do with by returning a pointer to that location.
```haskell
import "std/io.ink"

arena^ -> u64 ~> u64 -> u64 effectful = \a x: {
	u64 -> u64 f = \y: x + y;
	print "side effect\n";
	return f =:>> a =:> a; // moves f to a, and creates a pointer to that region in a
};

u64 main = {
	arena pool = arena_init 100;
	u64 -> u64 f = ^(effectful (&pool) 1);
	u64 three = f 2;
	print "After effect\n";
	return 0;
};
```

This gives Ink very explicit effect semantics, allowing an information pointer based notation for when partial effects happen, understanding that otherwise, side effectful computation can only occur at full application to a term.

## Parametric types
Types  may be parametric, and this can be notated in type definitions.

This may also be a good time to mention that you can define functions with symbol names, these can be infix or prefix in use.

``` haskell

//a generic pipe procedude
A -> (A -> B) -> B
|> = \val fun: fun val;

type Either L R = struct {
	enum {Left, Right} tag;
	union {
		L left;
		R right;
	} data;
};

u64 main = {
	Either u8 i8 applied_generic = {Left, left = 0};
	return applied_generic.data.left as u64;
};

```

An emergent behavior of the Ink typechecker has lead to an implicit `let` type inference feature, where because Ink will try to evaluate the type of a generic non function type and replace the definition with the evaluated type, you are allowed to use any arbitrary generic term not otherwise used in the scope to do implicit type inference. This can only work if the type is actually deducible with all the other type information present.

```haskell
u64 main = {
	u64 x = 0;
	let y = x + 6; // Ink knows y is u64
	return y;
};

```

## Typeclasses
Typeclasses are sometimes called interfaces, or protocols, or traits, but I was first introduced to them while programming Haskell, so to me they are typeclasses. I don't know what the original literature for this feature has to say about its naming.

Typeclasses need a name and a member parameter which represents a generic instance of that typeclass in subsequent member term definitions.
```haskell

typeclass Functor F {
	(A -> B) -> F A -> F B map;
}

```

Implementations then replace this generic term with the type implementing the typeclass. It should be noted that only named types can have typeclass instantiations. 
```haskell

type buffer T = [T];

byte_list implements Functor {
	(A -> B) -> buffer A -> buffer B
	map = \f data: {
		u64 var i = 0;
		buffer (B var) result = [ [0], data.len ];
		while i < data.len {
			result.ptr[i] = f (data.ptr[i]);
			i = i + 1;
		};
		return result;
	};
}

```

Generic types in any term may have a typeclass dependency. 
``` haskell

(Allocator A) => A -> T -> T^ mk_ptr = \alloc data: ...;

```

Typeclass members have the typeclass parameter distributed over them as a dependency.
``` haskell
typeclass Orderable O {
	O -> O -> i8 compare;
}

//is converted internally to

typeclass Orderable O {
	(Orderable O) => O -> O -> i8 compare;
}

```

## FFI
Ink has the ability to completely interface with C, there may be friction in some places, but you can run arbitrary C from Ink and arbitrary Ink from C.

To define external terms, aliases, or types, declare them in an `external` block.
```haskell
external {
	u8^ -> u8^ -> u64 -> u8 memcpy;
	u8^ -> u8 -> u64 -> u8 memset;
	u64 -> u8^ -> u64 -> u64 write;
	u64 -> u8^ malloc;
}

```

Note that `typedef struct name {} name` in C translates approximately to `type name = struct {}` in Ink, but any other non structure typedef is equivalent to an alias in Ink, not a type definition. 

To import local C files, you may import normally.
```haskell
external {
	import "emscripten_wrapper.h"
}
```

To import C standard library files, you may import globally.
```haskell
external {
	import global "SDL2/SDL.h"
}
```

Some FFI interfaces have already been generated for SDL2, netinet/in, and emscripten.

Enumerators and constants are not handled well by the FFI generator, so some of them have been defined manually as constants in Ink.

# Example, print formatting
```haskell
import "std/io.ink"
import "std/ffi.ink"

u64 main = {
	// A brief look into the allocator typeclass
	Arena pool = arena_init 512 ARENA_STATIC;
	u8^ buffer = (&pool) ## 10;
	u64 stack_allocated = 64;
	u64^ arena_allocated = stack_allocated =:> &pool;
	[u64] fat_allocated = stack_allocated =:: &pool;
	[u64] moved = fat_allocated =:>> &pool;

	String left = string_init (&pool) "first ";
	String right = zero " second\n" &pool;
	
	u64 numeric = 5;

	printf $ left +% numeric ++ right;
	return 0;
};
```

io.ink:
```haskell
import "string.ink"

String -> u64
print = \msg:
	write 1 ((msg.data.ptr) as (u8^)) (msg.data.len);

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

builtin.ink:
```haskell
constant null = 0;

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

A -> (A -> B) -> B
|> = \a f: f a;

(A -> B) -> A -> B
<| = \f a: f a;

alias uword = u64;
alias word = i64;
alias ubyte = u8;
alias byte = i8;
```

ffi.ink:
```haskell

external {
	u8^ -> u8^ -> u64 -> u8 memcpy;
	u8^ -> u8 -> u64 -> u8 memset;
	u64 -> u8^ -> u64 -> u64 write;
	u64 -> u8^ malloc;
}

```

# Example, HTTP Server
```haskell
import "std/netinet.ink"
import "std/io.ink"

constant BUFFER_SIZE = 16000;

type Server = struct {
	i32 domain;
	u16 port;
	i32 service;
	i32 protocol;
	i32 backlog;
	i32 socket;
	sockaddr_in^ address;
};

i32 -> u16 -> i32 -> i32 -> i32 -> u32 -> u64
server_init = \domain port service protocol backlog interface : {
	sockaddr_in_ink address = {
		sin_family = domain,
		sin_addr = {s_addr = htonl interface},
		sin_port = htons port
	};
	Server server = {
		domain, port, service, protocol, backlog,
		socket domain service protocol,
		(&(address as sockaddr_in))
	};
	if server.socket < 0 {
		print "Failed to initialize / connect to socket\n";
		return 0;
	};
	i32 bound = bind (server.socket) (server.address as u8^) ((sizeof sockaddr_in) as u32);
	if bound < 0 {
		print "Failed to bind socket\n";
		return 0;
	};
	i32 listening = listen (server.socket) (server.backlog);
	if listening < 0 {
		print "Failed to listen\n";
		return 0;
	};
	return launch_server &server;
};

Server^ -> u64
launch_server = \server:{
	Arena arena = arena_init (BUFFER_SIZE*2) ARENA_STATIC;
	u8^ buffer_region = (&arena) ## BUFFER_SIZE;
	[i8] buffer = [
		(buffer_region as i8^),
		BUFFER_SIZE
	];
	while 1 {
		print "Waiting for connection ...\n";
		u64 addrlen = sizeof sockaddr_in;
		sockaddr_in client_addr = {empty=0} as sockaddr_in;
		i32 new_socket =
			accept
				(server.socket)
				((&client_addr) as u8^)
				((&addrlen)     as socklen_t^);
		if new_socket < 0 {
			print "Error accepting connection\n";
		};
		u64 bytes_read =
			read
				new_socket
				(buffer.ptr as u8^)
				(buffer.len - 1);
		if bytes_read >= 0 {
			print buffer;
			print "\n";
		}
		else {
			print "Error reading buffer\n";
		};
		[i8] response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charser=UTF-8\r\n\r\n<!DOCTYPE html>\r\n<html><head>Hi from Ink</head></html>\r\n";
		write
			(new_socket as u64)
			(response.ptr as u8^)
			(response.len);
		close new_socket;
	};
	return 0;
};

u64 main = {
	return
		server_init
			AF_INET
			8080
			SOCK_STREAM
			0 10
			INADDR_ANY;
```

# Example, SDL2
```haskell
import "std/sdl2.ink"

u64 main = {
	SDL_Init SDL_INIT_VIDEO;
	SDL_Window^ window =
		SDL_CreateWindow
			"title"
			SDL_WINDOWPOS_UNDEFINED
			SDL_WINDOWPOS_UNDEFINED
			100 100
			SDL_WINDOW_SHOWN;
	SDL_Delay 2000;
	SDL_DestroyWindow window;
	SDL_Quit;
	return 0;
};
```

# Example, Web Assembly
```haskell
import "std/sdl2.ink"
import "std/emscripten.ink"
import "std/builtin.ink"

u8^ -> u8 emscripten_frame = \args: {
	Graphics^ g = (args as Graphics^);
	SDL_FRect rect = {
		x=0.0, y=0.0,
		w=500.0, h=500.0
	} as SDL_FRect;
	SDL_RenderClear (g.renderer);
		SDL_SetRenderDrawColor (g.renderer) 255 255 255 255;
		SDL_RenderFillRectF    (g.renderer) (&rect);
		SDL_SetRenderDrawColor (g.renderer) 0 0 0 0;
	SDL_RenderPresent (g.renderer);
	return 0;
};

type Graphics = struct {
	SDL_Window^ window;
	SDL_Renderer^ renderer;
};

u64 main = {
	SDL_Init SDL_INIT_EVERYTHING;
	SDL_Window^   window   = (null as SDL_Window^);
	SDL_Renderer^ renderer = (null as SDL_Renderer^);
	u64 w = canvas_get_width;
	u64 h = canvas_get_height;
	SDL_CreateWindowAndRenderer
		w h
		SDL_WINDOW_OPENGL
		(&window) (&renderer);
	SDL_SetWindowTitle window "wasm test";
	SDL_SetRenderDrawBlendMode renderer (SDL_BLENDMODE_BLEND as SDL_BlendMode);
	Graphics graphics = {window, renderer};
	emscripten_start_loop ((&graphics) as u8^);
	SDL_DestroyWindow window;
	SDL_DestroyRenderer renderer;
	SDL_QuitSubSystem SDL_INIT_EVERYTHING;
	SDL_Quit;
	return 0;
};
```
