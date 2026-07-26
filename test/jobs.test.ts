import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  JOB_STATE_DONE,
  JOB_STATE_ERROR,
  JOB_STATE_READY,
  JOB_STATE_TAKEN,
  type JobRow,
  runPendingJobs,
} from "../src/jobs";
import { addMinutes, nowStr, toStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";

const tenv = env as unknown as Env;

async function insertJob(over: Partial<JobRow> = {}): Promise<number> {
  const row = {
    name: "no-such-job",
    payload: null as string | null,
    run_at: null as string | null,
    state: JOB_STATE_READY,
    attempts: 0,
    taken_at: null as string | null,
    priority: 50,
    ...over,
  };
  const res = await tenv.DB.prepare(
    `INSERT INTO job (name, payload, run_at, state, attempts, taken_at, priority)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  )
    .bind(
      row.name,
      row.payload,
      row.run_at,
      row.state,
      row.attempts,
      row.taken_at,
      row.priority,
    )
    .run();
  return res.meta.last_row_id;
}

function getJob(id: number): Promise<JobRow | null> {
  return tenv.DB.prepare("SELECT * FROM job WHERE id = ?1")
    .bind(id)
    .first<JobRow>();
}

beforeEach(async () => {
  await tenv.DB.prepare("DELETE FROM job").run();
});

describe("runPendingJobs (job_runner.execute port)", () => {
  it("claims a ready job; a failing handler leaves it taken with attempts=1", async () => {
    const id = await insertJob(); // unknown name -> handler throws
    const done = await runPendingJobs(tenv);
    expect(done).toBe(0);
    const job = await getJob(id);
    expect(job?.state).toBe(JOB_STATE_TAKEN);
    expect(job?.attempts).toBe(1);
    expect(job?.taken_at).not.toBeNull();
  });

  it("does not pick up jobs scheduled further than 10 minutes out", async () => {
    const id = await insertJob({
      run_at: toStr(addMinutes(new Date(), 30)),
    });
    await runPendingJobs(tenv);
    expect((await getJob(id))?.state).toBe(JOB_STATE_READY);
  });

  it("picks up jobs whose run_at is within the +10min window", async () => {
    const id = await insertJob({
      run_at: toStr(addMinutes(new Date(), 5)),
    });
    await runPendingJobs(tenv);
    expect((await getJob(id))?.state).toBe(JOB_STATE_TAKEN);
  });

  it("retries a stale taken job and marks it error at JOB_MAX_ATTEMPTS", async () => {
    const id = await insertJob({
      state: JOB_STATE_TAKEN,
      attempts: 4,
      taken_at: toStr(addMinutes(new Date(), -31)),
    });
    await runPendingJobs(tenv);
    const job = await getJob(id);
    expect(job?.attempts).toBe(5);
    expect(job?.state).toBe(JOB_STATE_ERROR);
  });

  it("leaves a recently-taken job alone (30-min retry wait)", async () => {
    const id = await insertJob({
      state: JOB_STATE_TAKEN,
      attempts: 1,
      taken_at: nowStr(),
    });
    await runPendingJobs(tenv);
    const job = await getJob(id);
    expect(job?.attempts).toBe(1);
    expect(job?.state).toBe(JOB_STATE_TAKEN);
  });

  it("leaves done/error jobs alone", async () => {
    const doneId = await insertJob({ state: JOB_STATE_DONE });
    const errId = await insertJob({ state: JOB_STATE_ERROR, attempts: 5 });
    await runPendingJobs(tenv);
    expect((await getJob(doneId))?.state).toBe(JOB_STATE_DONE);
    expect((await getJob(errId))?.state).toBe(JOB_STATE_ERROR);
    expect((await getJob(errId))?.attempts).toBe(5);
  });
});
