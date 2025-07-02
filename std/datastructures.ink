import "std/allocators.ink"

type Maybe T = struct {
	enum {Just, Nothing} tag;
	T var val;
};

typeclass Stackable S {
	(S T)^ -> T -> (S T)^ push;
	(S T)^ -> T pop;
	(S T)^ -> T top;
}

typeclass Resizable R {
	R^ -> R^ resize; 
}

typeclass Indexed I {
	(I T)^ -> u64 -> T -> (I T)^ insert;
	(I T)^ -> u64 -> Maybe T remove;
	(I T)^ -> u64 -> Maybe T !!;
}

typeclass Functor F {
	(A -> B) -> (F A)^ -> F B map;
}
