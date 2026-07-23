export {};

declare global {
    const before: typeof beforeAll;
    const after: typeof afterAll;
}
