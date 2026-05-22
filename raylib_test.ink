import "std/ffi/raylib/raylib.ink"
import "std/io.ink"

u64 main = {
	u64 sw = 800;
	u64 sh = 800;
	InitWindow sw sh "example";
	SetTargetFPS 60;
	Color c = {255, 255, 255, 255};
	Color b = {0, 0, 0, 255};
	while !WindowShouldClose {
		BeginDrawing;
			ClearBackground b;
			DrawText "hello" 128 128 20 c;
		EndDrawing;
	};
	CloseWindow;
	return 0;
};
