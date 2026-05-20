echo "http server"
./ink -o server server.ink
echo "wasm"
./ink -o wasm wasm.ink -lSDL2main -lSDL2 -lSDL2_ttf -lSDL2_image -lSDL2_mixer -lm
emcc --emrun wasm.ink.c --bind -s WASM=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS='["png"]' -s USE_SDL_TTF=2 -s USE_SDL_MIXER=2 -lm -o wasm.html --shell-file wasm_template.html
echo "sdl2"
./ink -o window window.ink -lSDL2main -lSDL2 -lSDL2_ttf -lSDL2_image -lSDL2_mixer -lm
echo "array"
./ink -o array array.ink
echo "test"
./ink -o test test.ink
echo "format"
./ink -o format format.ink
echo "loop"
./ink -o loop loop.ink
echo "stack"
./ink -o stack stack.ink
echo "copy_closure"
./ink -o copy_closure copy_closure.ink
echo "effects"
./ink -o effects effects.ink
echo "mem_management"
./ink -o mem_management mem_management.ink
echo "funret"
./ink -o funret funret.ink
echo "funarg"
./ink -o funarg funarg.ink
echo "partial"
./ink -o partial partial.ink
echo "memory"
./ink -o memory memory.ink
echo "hello"
./ink -o hello hello.ink

