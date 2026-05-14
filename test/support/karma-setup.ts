// Tell the Emscripten WASM wrapper where to find the .wasm file relative to karma's base URL
if (!(globalThis as Record<string, unknown>).__WASM_BASE__) {
    (globalThis as Record<string, unknown>).__WASM_BASE__ = "/base/build/";
}
