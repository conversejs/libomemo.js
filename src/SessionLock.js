/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */

const jobQueue = {};

export function queueJobForNumber(number, runJob) {
    const runPrevious = jobQueue[number] || Promise.resolve();
    const runCurrent = (jobQueue[number] = runPrevious.then(runJob, runJob));
    runCurrent.then(() => {
        if (jobQueue[number] === runCurrent) {
            delete jobQueue[number];
        }
    });
    return runCurrent;
}
