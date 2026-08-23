// Only load .env.local when running locally — Vercel injects env vars directly.
if (!process.env.VERCEL) {
  try {
    require("dotenv").config({ path: ".env.local" });
  } catch (e) {
    // dotenv not installed — fine if env vars are already set another way
  }
}
const express = require("express");
const crypto = require("crypto");
const { kv } = require("@vercel/kv");

const app = express();
app.use(express.json({ limit: "10mb" }));

// If the request body isn't valid JSON, express.json() throws a parse error
// which Express's default handler turns into an HTML "Bad Request" page.
// The spec requires a JSON error body in every case, so catch that here.
app.use((err, req, res, next) => {
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }
  next(err);
});

// ---- persistence layer (Vercel KV instead of in-memory Map) ----

function freezeKey(freezeId) {
  return `freeze:${freezeId}`;
}

async function getFreezeRecord(freezeId) {
  return await kv.get(freezeKey(freezeId)); // returns null if missing
}

async function setFreezeRecord(freezeId, record) {
  await kv.set(freezeKey(freezeId), record);
}

// ================= shared helpers =================

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

function isUniqueArrayOfNonEmptyStrings(arr) {
  if (!Array.isArray(arr)) return false;
  const seen = new Set();
  for (const v of arr) {
    if (!isNonEmptyString(v)) return false;
    if (seen.has(v)) return false;
    seen.add(v);
  }
  return true;
}

function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function compareUtf8(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return Buffer.compare(ba, bb);
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;

  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }

  const aKeys = Object.keys(a).sort();
  const bKeys = Object.keys(b).sort();
  if (aKeys.length !== bKeys.length) return false;
  if (!aKeys.every((k, i) => k === bKeys[i])) return false;
  return aKeys.every((k) => deepEqual(a[k], b[k]));
}

function round12(x) {
  return Number(x.toFixed(12));
}

function isFiniteNonNegNumber(v) {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

function isSafeNonNegInt(v) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && Number.isSafeInteger(v);
}

// ================= FREEZE PHASE =================

// Only the bare minimum needed to accept the request at all: candidate must be
// an object with a valid, unique, non-empty name. Everything else (files shape,
// loadable, digests, unsupportedReason) is validated per-candidate later and
// results in that candidate's status being "invalid" rather than a global 400 —
// per spec: "If a candidate's files are invalid, return an empty inventory and
// null totalBytes and packageDigest" (i.e. handled gracefully, not rejected).
function validateCandidateShape(candidate) {
  if (typeof candidate !== "object" || candidate === null) return false;
  if (!isNonEmptyString(candidate.name)) return false;
  return true;
}

// Files are valid only if: present, a plain object, non-empty, and every
// value is a string. (Object keys are inherently unique in JS.)
function candidateFilesValid(files) {
  if (typeof files !== "object" || files === null || Array.isArray(files)) return false;
  const keys = Object.keys(files);
  if (keys.length === 0) return false;
  return keys.every((k) => typeof files[k] === "string");
}

function validateFreezeRequest(body) {
  if (typeof body !== "object" || body === null) return false;
  if (!isNonEmptyString(body.freezeId) || body.freezeId.length > 128) return false;
  if (!isNonEmptyString(body.calibrationDigest)) return false;
  if (!isNonEmptyString(body.tokenizerDigest)) return false;
  if (!isUniqueArrayOfNonEmptyStrings(body.allowedUnsupportedReasons ?? [])) return false;
  if (!Array.isArray(body.candidates) || body.candidates.length === 0) return false;

  const names = new Set();
  for (const c of body.candidates) {
    if (!validateCandidateShape(c)) return false;
    if (names.has(c.name)) return false;
    names.add(c.name);
  }
  return true;
}

function computeInventory(files) {
  const items = Object.keys(files).map((name) => {
    const bytes = Buffer.from(files[name], "utf8");
    return { name, bytes: bytes.length, sha256: sha256Hex(bytes) };
  });
  items.sort((a, b) => compareUtf8(a.name, b.name));
  const totalBytes = items.reduce((sum, i) => sum + i.bytes, 0);
  return { inventory: items, totalBytes };
}

function computePackageDigest(inventory) {
  const ordered = inventory.map((i) => ({ name: i.name, bytes: i.bytes, sha256: i.sha256 }));
  const jsonStr = JSON.stringify(ordered);
  return sha256Hex(Buffer.from(jsonStr, "utf8"));
}

function decideCandidateStatus(candidate, body) {
  const allowedReasons = new Set(body.allowedUnsupportedReasons ?? []);
  const reasonCodes = [];

  if (isNonEmptyString(candidate.unsupportedReason)) {
    if (allowedReasons.has(candidate.unsupportedReason)) {
      return { status: "unsupported", reasonCodes: [] };
    } else {
      return { status: "invalid", reasonCodes: ["UNALLOWED_UNSUPPORTED_REASON"] };
    }
  }

  if (candidate.loadable !== true) reasonCodes.push("NOT_LOADABLE");
  if (candidate.calibrationDigest !== body.calibrationDigest) reasonCodes.push("CALIBRATION_MISMATCH");
  if (candidate.tokenizerDigest !== body.tokenizerDigest) reasonCodes.push("TOKENIZER_MISMATCH");

  return {
    status: reasonCodes.length === 0 ? "frozen" : "invalid",
    reasonCodes,
  };
}

function buildFreezeResponse(body) {
  const results = body.candidates.map((candidate) => {
    if (!candidateFilesValid(candidate.files)) {
      // Per spec: invalid files -> empty inventory, null totals, but the
      // request as a whole is still accepted.
      return {
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: ["INVALID_INPUT"],
      };
    }

    const { inventory, totalBytes } = computeInventory(candidate.files);
    const packageDigest = computePackageDigest(inventory);
    const { status, reasonCodes } = decideCandidateStatus(candidate, body);

    return { name: candidate.name, status, inventory, totalBytes, packageDigest, reasonCodes };
  });

  results.sort((a, b) => compareUtf8(a.name, b.name));
  return { freezeId: body.freezeId, candidates: results };
}

async function handleFreeze(body, res) {
  if (!validateFreezeRequest(body)) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }

  const existing = await getFreezeRecord(body.freezeId);

  if (existing) {
    if (deepEqual(existing.requestBody, body)) {
      return res.status(200).json(existing.response);
    } else {
      return res.status(409).json({ error: "FREEZE_ID_CONFLICT" });
    }
  }

  const response = buildFreezeResponse(body);
  await setFreezeRecord(body.freezeId, { requestBody: body, response });
  return res.status(200).json(response);
}

// ================= SELECT PHASE =================

function validateSelectShape(body) {
  if (typeof body !== "object" || body === null) return false;
  if (!isNonEmptyString(body.freezeId)) return false;
  if (!Array.isArray(body.candidates)) return false;
  if (!Array.isArray(body.rows)) return false;
  if (typeof body.policy !== "object" || body.policy === null) return false;
  return true;
}

function recomputeFromInventory(inventory) {
  if (!Array.isArray(inventory)) return { totalBytes: null, packageDigest: null, ok: false };
  for (const item of inventory) {
    if (
      typeof item !== "object" || item === null ||
      !isNonEmptyString(item.name) ||
      !isSafeNonNegInt(item.bytes) ||
      !isNonEmptyString(item.sha256)
    ) {
      return { totalBytes: null, packageDigest: null, ok: false };
    }
  }
  const sorted = [...inventory].sort((a, b) => compareUtf8(a.name, b.name));
  const totalBytes = sorted.reduce((sum, i) => sum + i.bytes, 0);
  const packageDigest = computePackageDigest(sorted);
  return { totalBytes, packageDigest, ok: true };
}

function validatePolicy(policy, candidateNames) {
  const codes = [];
  if (!isSafeNonNegInt(policy.maxBytes)) codes.push("INVALID_POLICY");
  if (
    typeof policy.aggregateFloor !== "number" ||
    !Number.isFinite(policy.aggregateFloor) ||
    policy.aggregateFloor < 0 ||
    policy.aggregateFloor > 1
  ) codes.push("INVALID_POLICY");

  if (typeof policy.requiredSlices !== "object" || policy.requiredSlices === null) {
    codes.push("INVALID_POLICY");
  } else {
    for (const v of Object.values(policy.requiredSlices)) {
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1) codes.push("INVALID_POLICY");
    }
  }

  if (!isFiniteNonNegNumber(policy.maxLatencyMs)) codes.push("INVALID_POLICY");

  if (!Array.isArray(policy.candidateOrder)) {
    codes.push("INVALID_POLICY");
  } else {
    const orderSet = new Set(policy.candidateOrder);
    const sameSize = orderSet.size === policy.candidateOrder.length && orderSet.size === candidateNames.size;
    const sameMembers = sameSize && [...orderSet].every((n) => candidateNames.has(n));
    if (!sameSize || !sameMembers) codes.push("INVALID_POLICY");
  }

  return codes.length > 0;
}

function computeAccuracyForCandidate(candName, rows, requiredSliceNames) {
  for (const row of rows) {
    const p = row?.predictions?.[candName];
    if (p !== 0 && p !== 1) {
      return { aggregate: null, slices: null, predictionsInvalid: true };
    }
  }

  let correct = 0;
  const sliceCorrect = {};
  const sliceTotal = {};

  for (const row of rows) {
    const p = row.predictions[candName];
    const isMatch = p === row.label ? 1 : 0;
    correct += isMatch;

    if (requiredSliceNames.has(row.slice)) {
      sliceCorrect[row.slice] = (sliceCorrect[row.slice] || 0) + isMatch;
      sliceTotal[row.slice] = (sliceTotal[row.slice] || 0) + 1;
    }
  }

  const aggregate = rows.length > 0 ? round12(correct / rows.length) : 0;

  const slices = {};
  for (const sliceName of requiredSliceNames) {
    if (sliceTotal[sliceName] > 0) {
      slices[sliceName] = round12(sliceCorrect[sliceName] / sliceTotal[sliceName]);
    }
  }

  return { aggregate, slices, predictionsInvalid: false };
}

async function handleSelect(body, res) {
  if (!validateSelectShape(body)) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }

  const { freezeId, candidates: submitted, rows, policy } = body;
  const stored = await getFreezeRecord(freezeId);

  const submittedNames = new Set(submitted.map((c) => c && c.name));
  const requiredSliceNames = new Set(
    policy && typeof policy.requiredSlices === "object" && policy.requiredSlices !== null
      ? Object.keys(policy.requiredSlices)
      : []
  );

  const policyInvalid = !stored ? true : validatePolicy(policy, submittedNames);

  const storedByName = new Map();
  if (stored) {
    for (const c of stored.response.candidates) storedByName.set(c.name, c);
  }

  let lineageOk = false;
  if (stored) {
    const sortedSubmitted = [...submitted].sort((a, b) => compareUtf8(a?.name ?? "", b?.name ?? ""));
    const sortedStored = [...stored.response.candidates].sort((a, b) => compareUtf8(a.name, b.name));
    lineageOk = deepEqual(sortedSubmitted, sortedStored);
  }

  const results = submitted.map((cand) => {
    const name = cand?.name;
    const codes = new Set();

    const storedCand = storedByName.get(name);
    const isFrozen = !!storedCand && storedCand.status === "frozen";
    if (!isFrozen) codes.add("NOT_FROZEN");
    if (!lineageOk) codes.add("INVALID_LINEAGE");
    if (policyInvalid) codes.add("INVALID_POLICY");

    const recomputed = recomputeFromInventory(cand?.inventory);
    if (!recomputed.ok) codes.add("INVALID_MANIFEST");

    const { aggregate, slices, predictionsInvalid } = computeAccuracyForCandidate(
      name,
      rows,
      requiredSliceNames
    );
    if (predictionsInvalid) codes.add("INVALID_PREDICTIONS");

    if (!predictionsInvalid && policy && typeof policy.aggregateFloor === "number") {
      if (aggregate < policy.aggregateFloor) codes.add("AGGREGATE_FLOOR");
    }

    const outSlices = {};
    if (!predictionsInvalid) {
      for (const sliceName of requiredSliceNames) {
        if (!(sliceName in slices)) {
          codes.add(`MISSING_SLICE:${sliceName}`);
        } else {
          outSlices[sliceName] = slices[sliceName];
          if (slices[sliceName] < policy.requiredSlices[sliceName]) {
            codes.add(`SLICE_FLOOR:${sliceName}`);
          }
        }
      }
    }

    let totalBytes = recomputed.ok ? recomputed.totalBytes : null;
    if (recomputed.ok && policy && isSafeNonNegInt(policy.maxBytes)) {
      if (totalBytes > policy.maxBytes) codes.add("SIZE_LIMIT");
    }

    let latencyMs = null;
    const rawLatency = body.latencies ? body.latencies[name] : undefined;
    if (isFiniteNonNegNumber(rawLatency)) {
      latencyMs = rawLatency;
      if (policy && isFiniteNonNegNumber(policy.maxLatencyMs) && latencyMs > policy.maxLatencyMs) {
        codes.add("LATENCY_LIMIT");
      }
    } else {
      codes.add("LATENCY_LIMIT");
      latencyMs = null;
    }

    const admitted = codes.size === 0;
    const sortedCodes = [...codes].sort(compareUtf8);

    return {
      name,
      aggregate: predictionsInvalid ? null : aggregate,
      slices: predictionsInvalid ? null : outSlices,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes: sortedCodes,
      __totalBytesForSort: totalBytes,
      __latencyForSort: latencyMs,
    };
  });

  const orderIndex = new Map();
  if (Array.isArray(policy?.candidateOrder)) {
    policy.candidateOrder.forEach((n, i) => orderIndex.set(n, i));
  }
  results.sort((a, b) => {
    const ai = orderIndex.has(a.name) ? orderIndex.get(a.name) : Infinity;
    const bi = orderIndex.has(b.name) ? orderIndex.get(b.name) : Infinity;
    if (ai !== bi) return ai - bi;
    return compareUtf8(a.name, b.name);
  });

  const admittedResults = results.filter((r) => r.admitted);
  let winner = null;
  for (const r of admittedResults) {
    if (!winner) {
      winner = r;
      continue;
    }
    if (r.__totalBytesForSort !== winner.__totalBytesForSort) {
      if (r.__totalBytesForSort < winner.__totalBytesForSort) winner = r;
      continue;
    }
    if (r.__latencyForSort !== winner.__latencyForSort) {
      if (r.__latencyForSort < winner.__latencyForSort) winner = r;
      continue;
    }
    const rOrder = orderIndex.has(r.name) ? orderIndex.get(r.name) : Infinity;
    const wOrder = orderIndex.has(winner.name) ? orderIndex.get(winner.name) : Infinity;
    if (rOrder < wOrder) winner = r;
  }

  const packageManifest = winner ? storedByName.get(winner.name) ?? null : null;

  const cleanResults = results.map(({ __totalBytesForSort, __latencyForSort, ...rest }) => rest);

  return res.status(200).json({
    freezeId,
    selected: winner ? winner.name : null,
    results: cleanResults,
    packageManifest,
  });
}

// ================= express wiring =================

app.post("/quantize", async (req, res) => {
  const body = req.body;

  try {
    if (body?.phase === "freeze") {
      if (!validateFreezeRequest(body)) {
        console.log("FREEZE validation failed for body:", JSON.stringify(body));
      }
      return await handleFreeze(body, res);
    } else if (body?.phase === "select") {
      if (!validateSelectShape(body)) {
        console.log("SELECT validation failed for body:", JSON.stringify(body));
      }
      return await handleSelect(body, res);
    } else {
      console.log("Unknown/missing phase. Body was:", JSON.stringify(body));
      return res.status(400).json({ error: "INVALID_INPUT" });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
});

// Only start a listener when run locally (node server.js).
// On Vercel, the platform imports `app` directly as a serverless handler.
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`listening on port ${PORT}`));
}

module.exports = app;