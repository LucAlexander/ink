import "std/datastructures.ink"

constant MAP_BUCKET_COUNT = 32;

type Map K V = struct{
	Arena^ mem;
	(K -> u64) hash;
	[MapBucket K V] var buckets;
};

type MapBucket K V = struct{
	u64 var hash;
	K var key;
	V var value;
	(MapBucket K V)^ var left;
	(MapBucket K V)^ var right;
};

Map K V -> u8
map_init = \map: {
	map.buckets = arena ## (MAP_BUCKET_COUNT * sizeof MapBucket K V);
	return 1;
};

Map K V -> K -> V -> u8
put = \map key val: {
	u64 hashed = map.hash key;
	return map_bucket_insert &(map.buckets[hashed%MAP_BUCKET_COUNT]) key val hashed;
};

(MapBucket K V)^ -> K -> V -> u64 -> u8
map_bucket_insert = \bucket key val hash: {
	if hash < bucket.hash {
		if bucket.left == null {
			bucket.left = {hash, key, val, null as u8^, null as u8^};
			return 1;
		}
		return map_bucket_insert bucket.left key val hash;
	}
	else if hash > bucket.hash {
		if bucket.right == null {
			bucket.right = {hash, key, val, null as u8^, null as u8^};
			return 1;
		}
		return map_bucket_insert bucket.right key val hash;
	}
	bucket.key = key;
	bucket.val = val;
	return 1;
}

(MapBucket K V)^ -> K -> u64 -> Maybe V
map_bucket_get = \bucket key hash: {
	if hash < bucket.hash {
		if bucket.left == null {
			return {Nothing};
		}
		return map_bucket_get bucket.left key hash;
	}
	else if hash > bucket.hash {
		if bucket.right == null {
			return {Nothing};
		}
		return map_bucket_get bucket.right key hash;
	}
	return {Just, bucket.val};
}

Map K V -> K -> Maybe V
get = \map key: {
	u64 hash = map.hash key;
	return map_bucket_get &(map.buckets[hash % MAP_BUCKET_COUNT]) key hash;
};
