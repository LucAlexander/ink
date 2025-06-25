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
