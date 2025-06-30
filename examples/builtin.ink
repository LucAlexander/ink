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

alias uword = u64;
alias word = i64;
alias ubyte = u8;
alias byte = i8;

