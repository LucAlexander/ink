import "sdl2.ink"

u64 main = {
	SDL_Init SDL_INIT_VIDEO;
	SDL_Window^ window =
		SDL_CreateWindow
			"title"
			SDL_WINDOWPOS_UNDEFINED
			SDL_WINDOWPOS_UNDEFINED
			100 100
			SDL_WINDOW_SHOWN;
	SDL_Delay 2000;
	SDL_DestroyWindow window;
	SDL_Quit;
	return 0;
};
