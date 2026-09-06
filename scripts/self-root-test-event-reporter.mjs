import { Transform } from "node:stream";

let emittedBytes = 0;
let emittedRecords = 0;

// Emit only the bounded fields used by the post-run accounting verifier.  The
// ordinary Node reporter exit status is not sufficient evidence: a reporter or
// worker can terminate after a partial successful prefix.  This JSONL stream
// lets the wrapper prove the complete expected topology reached run completion.
export default new Transform({
  writableObjectMode: true,
  transform(event, _encoding, callback) {
    const data = event?.data ?? {};
    const record = { type: event?.type };
    if (typeof data.name === "string") record.name = data.name;
    if (typeof data.file === "string") record.file = data.file;
    if (Number.isSafeInteger(data.nesting)) record.nesting = data.nesting;
    if (Number.isSafeInteger(data.testNumber)) record.testNumber = data.testNumber;
    if (Number.isSafeInteger(data.count)) record.count = data.count;
    if (typeof data.skip === "string" || typeof data.skip === "boolean") record.skip = data.skip;
    if (typeof data.todo === "string" || typeof data.todo === "boolean") record.todo = data.todo;
    if (event?.type === "test:summary") {
      record.success = data.success;
      if (data.counts && typeof data.counts === "object") {
        record.counts = Object.fromEntries(Object.entries(data.counts)
          .filter(([, value]) => Number.isSafeInteger(value)));
      }
    }
    const line = `${JSON.stringify(record)}\n`;
    emittedBytes += Buffer.byteLength(line);
    emittedRecords += 1;
    if (emittedBytes > 2 * 1024 * 1024 || emittedRecords > 4_096) {
      callback(new Error("self-root test event stream exceeded its bounded evidence limit"));
      return;
    }
    callback(null, line);
  }
});
