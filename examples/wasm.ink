import "sdl2.ink"
import "emscripten.ink"
import "builtin.ink"

u8^ -> u8 emscripten_frame = \args: {
	Graphics^ g = (args as Graphics^);
	SDL_FRect rect = {
		x=0.0, y=0.0,
		w=500.0, h=500.0
	} as SDL_FRect;
	SDL_RenderClear (g.renderer);
		SDL_SetRenderDrawColor (g.renderer) 255 255 255 255;
		SDL_RenderFillRectF    (g.renderer) (&rect);
		SDL_SetRenderDrawColor (g.renderer) 0 0 0 0;
	SDL_RenderPresent (g.renderer);
	return 0;
};

type Graphics = struct {
	SDL_Window^ window;
	SDL_Renderer^ renderer;
};

u64 main = {
	SDL_Init SDL_INIT_EVERYTHING;
	SDL_Window^   window   = (null as SDL_Window^);
	SDL_Renderer^ renderer = (null as SDL_Renderer^);
	u64 w = canvas_get_width;
	u64 h = canvas_get_height;
	SDL_CreateWindowAndRenderer
		w h
		SDL_WINDOW_OPENGL
		(&window) (&renderer);
	SDL_SetWindowTitle window "wasm test";
	SDL_SetRenderDrawBlendMode renderer (SDL_BLENDMODE_BLEND as SDL_BlendMode);
	Graphics graphics = {window, renderer};
	emscripten_start_loop ((&graphics) as u8^);
	SDL_DestroyWindow window;
	SDL_DestroyRenderer renderer;
	SDL_QuitSubSystem SDL_INIT_EVERYTHING;
	SDL_Quit;
	return 0;
};
