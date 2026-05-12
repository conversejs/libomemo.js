// Tell the Emscripten WASM wrapper where to find the .wasm file relative to karma's base URL
if (typeof globalThis.__WASM_BASE__ === "undefined") {
    globalThis.__WASM_BASE__ = "/base/build/";
}
