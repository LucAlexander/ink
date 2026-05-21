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
alias cstr = i8^;

[u8] -> [u8] -> u64
builtin_strcmp = \x y: {
	if (x.len) != (y.len) {
		return 0;
	}
	for u64 var i = 0; i < (x.len); i = i + 1 {
		if x[i] != (y[i]) {
			return 0;
		}
	}
	return 1;
};
