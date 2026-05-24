import "std/allocators.ink"
import "std/functional.ink"

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

typeclass Sliceable S {
	(S A)^ -> u64 -> u64 -> S A uslice;
	(S A)^ -> i64 -> i64 -> S A slice;
}

typeclass Orderable C {
	C -> C -> i8 compare;
}

typeclass Copyable C {
	C^ -> C copy;
}
