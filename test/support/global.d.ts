export {};

declare global {
    let __WASM_BASE__: string | undefined;
    const before: typeof beforeAll;
    const after: typeof afterAll;
}
