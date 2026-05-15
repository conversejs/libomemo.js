const jobQueue: Record<string, Promise<unknown>> = {};

/** Ensures operations for a given address execute sequentially, preventing race conditions. */
export function queueJobForNumber<T>(number: string, runJob: () => Promise<T>): Promise<T> {
    const runPrevious = jobQueue[number] ?? Promise.resolve();
    const runCurrent = (jobQueue[number] = runPrevious.then(runJob, runJob));

    return runCurrent.then((T) => {
        if (jobQueue[number] === runCurrent) {
            delete jobQueue[number];
        }
        return T;
    });
}
