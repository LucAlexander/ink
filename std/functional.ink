import "std/builtin.ink"

alias Bool = u8;

type Maybe T = struct {
	enum {Just, Nothing} tag;
	T var val;
};

type Either L R = struct {
	enum {Left, Right} tag;
	union {
		L left;
		R right;
	} val;
};

typeclass Functor F {
	(A -> B) -> (F A)^ -> F B map;
}

typeclass Monoid M {
	M -> M -> M madd;
	M neutral;
}

alias Nat = u64;
alias Int = i64;

Nat implements Monoid {
	Nat -> Nat -> Nat madd = \a b: a + b;
	Nat neutral = 0;
}

Int implements Monoid {
	Int -> Int -> Int madd = \a b: a + b;
	Int neutral = 0;
}

Maybe implements Functor {
	(A -> B) -> (Maybe A)^ -> Maybe B
	map = \f (Just v): {Just, f v};
		| \f m@(Nothing): m; 
}


