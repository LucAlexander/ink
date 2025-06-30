#include <inttypes.h>
#include "emscripten.h"
extern uint8_t usr_ink_emscripten_frame(uint8_t*);
void process_frame(void* args){
	usr_ink_emscripten_frame(args);
}
uint8_t emscripten_start_loop(uint8_t* args){
	emscripten_set_main_loop_arg(process_frame, args, 0, 1);
	return 0;
}
EM_JS(int, canvas_get_width, (), {
  return window.screen.width;
});

EM_JS(int, canvas_get_height, (), {
  return window.screen.height;
});
