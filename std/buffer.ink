import "std/datastructures.ink"

type Buffer T = struct {
	Arena^ mem;
	T var^ var buffer;
	u64 var size;
	u64 var capacity;
};

Buffer implements Resizable {
	(Buffer T)^ -> (Buffer T)^
	resize = \buffer:{
		if buffer.size == (buffer.capacity) {
			buffer.capacity = buffer.capacity * 2;
			T var^ new = buffer.mem ## (buffer.capacity * sizeof T);
			for u64 var i = 0; i < (buffer.size); i = i + 1 {
				new[i] = buffer.buffer[i];
			};
			buffer.buffer = new;
		};
		return buffer;
	};
}

Buffer implements Stackable {
	(Buffer T)^ -> T -> (Buffer T)^
	push = \buffer value: {
		resize buffer;
		buffer.buffer[buffer.size] = value;
		buffer.size = buffer.size + 1;
		return buffer;
	};

	(Buffer T)^ -> T
	pop = \buffer: {
		buffer.size = buffer.size - 1;
		return buffer.buffer[buffer.size];
	};

	(Buffer T)^ -> T
	top = \buffer: buffer.buffer[buffer.size - 1];
}

Buffer implements Indexed {
	(Buffer T)^ -> u64 -> T -> Maybe (Buffer T^)
	insert = \buffer index value: {
		if index >= (buffer.size) {
			return {Nothing};
		};
		resize buffer;
		for u64 var i = index; i < (buffer.size); i = i + 1 {
			buffer.buffer[i + 1] = buffer.buffer[i];
		};
		buffer.buffer[index] = value;
		return {Just, buffer};
	};

	(Buffer T)^ -> u64 -> Maybe T
	remove = \buffer index: {
		if index >= (buffer.size) {
			return {Nothing};
		};
		T val = buffer.buffer[index];
		for u64 var i = index; i < (buffer.size - 1); i = i + 1 {
			buffer.buffer[i] = buffer.buffer[i + 1];
		};
		return {Just, val};
	};

	(Buffer T)^ -> u64 -> Maybe T
	!! = \buffer index: {
		if index >= (buffer.size){
			return {Nothing};
		};
		return {Just, buffer.buffer[index]};
	};
}

Buffer implements Functor {
	(A -> B) -> (Buffer A)^ -> Buffer B
	map = \function buffer: {
		Buffer B new = {
			mem = buffer.mem,
			buffer = buffer.mem ## (buffer.capacity * sizeof B),
			size = buffer.size,
			capacity = buffer.capacity
		};
		for u64 var i = 0;i<(buffer.size);i = i + 1{
			new.buffer[i] = function $ buffer.buffer[i];
		};
		return new;
	};
}

