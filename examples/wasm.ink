import "sdl2.ink"
import "emscripten.ink"
import "builtin.ink"

u8^ -> u8 emscripten_frame = \args: 0;

u64 main = {
	SDL_Init SDL_INIT_VIDEO;
	SDL_Window^ window =
		SDL_CreateWindow
			"wasm test"
			SDL_WINDOWPOS_UNDEFINED
			SDL_WINDOWPOS_UNDEFINED
			100 100
			SDL_WINDOW_SHOWN;
	emscripten_start_loop (null as u8^);
	SDL_DestroyWindow window;
	SDL_Quit;
	return 0;
};
