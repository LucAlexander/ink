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

