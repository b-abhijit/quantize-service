const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// In-memory ledger: freezeId -> { fingerprint, response, candidatesByName }
const freezeStore = new Map();

// ---------- generic helpers ----------

function isNonEmptyStr(s, maxLen = Infinity) {
  return typeof s === "string" && s.length > 0 && s.length <= maxLen;
}

function isFiniteNumber(n) {
  return typeof n === "number" && Number.isFinite(n);
}

function isSafeNonNegInt(n) {
  return typeof n === "number" && Number.isInteger(n) && n >= 0 && Number.isSafeInteger(n);
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function utf8ByteCompare(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function dedupeSortCodes(codes) {
  return Array.from(new Set(codes)).sort(utf8ByteCompare);
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (typeof a === "object") {
    const ak = Object.keys(a), bk = Object.keys(b);
    if (ak.length !== bk.length) return false;
    return ak.every(k => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]));
  }
  return false;
}

function canonicalStringify(value) {
  // sorts object keys recursively so field re-ordering doesn't count as "different"
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalStringify).join(",") + "]";
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(value[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

// ---------- inventory / digest ----------

function buildInventory(files) {
  const entries = Object.keys(files).map(name => {
    const buf = Buffer.from(files[name], "utf8");
    return { name, bytes: buf.length, sha256: sha256Hex(buf) };
  });
  entries.sort((a, b) => utf8ByteCompare(a.name, b.name));
  return entries;
}

function computePackageDigest(inventory) {
  // inventory items already have keys in name,bytes,sha256 order (insertion order)
  const json = JSON.stringify(inventory);
  return sha256Hex(Buffer.from(json, "utf8"));
}

function computeManifest(files) {
  const inventory = buildInventory(files);
  const totalBytes = inventory.reduce((s, e) => s + e.bytes, 0);
  const packageDigest = computePackageDigest(inventory);
  return { inventory, totalBytes, packageDigest };
}

// ---------- FREEZE phase ----------

function validateFreezeEnvelope(body) {
  if (!isNonEmptyStr(body.freezeId, 128)) return false;
  if (!isNonEmptyStr(body.calibrationDigest)) return false;
  if (!isNonEmptyStr(body.tokenizerDigest)) return false;
  if (!Array.isArray(body.candidates) || body.candidates.length === 0) return false;
  if (!Array.isArray(body.allowedUnsupportedReasons)) return false;

  const reasons = body.allowedUnsupportedReasons;
  if (!reasons.every(r => isNonEmptyStr(r))) return false;
  if (new Set(reasons).size !== reasons.length) return false;

  const names = body.candidates.map(c => c && c.name);
  if (!names.every(n => isNonEmptyStr(n))) return false;
  if (new Set(names).size !== names.length) return false;

  return true;
}

function isFilesObjectValid(files) {
  return (
    files && typeof files === "object" && !Array.isArray(files) &&
    Object.keys(files).length > 0 &&
    Object.values(files).every(v => typeof v === "string")
  );
}

function classifyCandidate(candidate, req) {
  if (!candidate || typeof candidate !== "object" ||
      !isNonEmptyStr(candidate.name) || !isFilesObjectValid(candidate.files)) {
    return {
      name: candidate && typeof candidate.name === "string" ? candidate.name : "",
      status: "invalid",
      inventory: [],
      totalBytes: null,
      packageDigest: null,
      reasonCodes: ["INVALID_INPUT"],
    };
  }

  const { inventory, totalBytes, packageDigest } = computeManifest(candidate.files);

  const reasonCodes = [];
  let skipNormalChecks = false;

  if (isNonEmptyStr(candidate.unsupportedReason)) {
    if (req.allowedUnsupportedReasons.includes(candidate.unsupportedReason)) {
      skipNormalChecks = true;
    } else {
      reasonCodes.push("UNALLOWED_UNSUPPORTED_REASON");
    }
  }

  if (!skipNormalChecks) {
    if (candidate.loadable !== true) reasonCodes.push("NOT_LOADABLE");
    if (candidate.calibrationDigest !== req.calibrationDigest) reasonCodes.push("CALIBRATION_MISMATCH");
    if (candidate.tokenizerDigest !== req.tokenizerDigest) reasonCodes.push("TOKENIZER_MISMATCH");
  }

  let status;
  if (skipNormalChecks) status = "unsupported";
  else if (reasonCodes.length === 0) status = "frozen";
  else status = "invalid";

  return {
    name: candidate.name,
    status,
    inventory,
    totalBytes,
    packageDigest,
    reasonCodes: dedupeSortCodes(reasonCodes),
  };
}

function buildFreezeResponse(body) {
  const candidates = body.candidates
    .map(c => classifyCandidate(c, body))
    .sort((a, b) => utf8ByteCompare(a.name, b.name));
  return { freezeId: body.freezeId, candidates };
}

function handleFreeze(body, res) {
  if (!validateFreezeEnvelope(body)) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }

  const key = body.freezeId;
  const fingerprint = canonicalStringify(body);

  if (freezeStore.has(key)) {
    const record = freezeStore.get(key);
    if (record.fingerprint === fingerprint) {
      return res.status(200).json(record.response);
    }
    return res.status(409).json({ error: "FREEZE_ID_CONFLICT" });
  }

  const response = buildFreezeResponse(body);

  // keep raw candidate files around so `select` can recompute manifests independently
  const filesByName = {};
  for (const c of body.candidates) {
    if (c && isNonEmptyStr(c.name) && isFilesObjectValid(c.files)) {
      filesByName[c.name] = c.files;
    }
  }

  freezeStore.set(key, { fingerprint, response, filesByName });
  return res.status(200).json(response);
}

// ---------- SELECT phase ----------

function validateSelectEnvelope(body) {
  return (
    Array.isArray(body.candidates) &&
    Array.isArray(body.rows) &&
    body.policy && typeof body.policy === "object" && !Array.isArray(body.policy)
  );
}

function validatePolicy(policy, candidateNames) {
  const errors = [];

  if (!isSafeNonNegInt(policy.maxBytes)) errors.push("INVALID_POLICY");
  if (!isFiniteNumber(policy.aggregateFloor) || policy.aggregateFloor < 0 || policy.aggregateFloor > 1) {
    errors.push("INVALID_POLICY");
  }
  if (!isFiniteNumber(policy.maxLatencyMs) || policy.maxLatencyMs < 0) errors.push("INVALID_POLICY");

  if (policy.requiredSlices && typeof policy.requiredSlices === "object") {
    for (const v of Object.values(policy.requiredSlices)) {
      if (!isFiniteNumber(v) || v < 0 || v > 1) errors.push("INVALID_POLICY");
    }
  } else {
    errors.push("INVALID_POLICY");
  }

  if (!Array.isArray(policy.candidateOrder)) {
    errors.push("INVALID_POLICY");
  } else {
    const orderSet = new Set(policy.candidateOrder);
    const nameSet = new Set(candidateNames);
    const sameSet =
      orderSet.size === nameSet.size &&
      [...orderSet].every(n => nameSet.has(n));
    if (!sameSet) errors.push("INVALID_POLICY");
  }

  return errors.length > 0;
}

function computeAccuracy(rows, candidateName) {
  let total = 0, correct = 0;
  const sliceTotals = {}, sliceCorrect = {};
  let sawAnyRow = false;
  let predictionsValid = true;

  for (const row of rows) {
    sawAnyRow = true;
    const pred = row && row.predictions ? row.predictions[candidateName] : undefined;
    const label = row ? row.label : undefined;
    const slice = row ? row.slice : undefined;

    if ((pred !== 0 && pred !== 1) || (label !== 0 && label !== 1) || !isNonEmptyStr(slice)) {
      predictionsValid = false;
      continue;
    }

    total += 1;
    const isCorrect = pred === label ? 1 : 0;
    correct += isCorrect;
    sliceTotals[slice] = (sliceTotals[slice] || 0) + 1;
    sliceCorrect[slice] = (sliceCorrect[slice] || 0) + isCorrect;
  }

  if (!sawAnyRow || !predictionsValid || total === 0) {
    return { aggregate: null, slices: null, valid: false };
  }

  const round12 = x => Math.round(x * 1e12) / 1e12;
  const aggregate = round12(correct / total);
  const slices = {};
  for (const s of Object.keys(sliceTotals)) {
    slices[s] = round12(sliceCorrect[s] / sliceTotals[s]);
  }
  return { aggregate, slices, valid: true };
}

function handleSelect(body, res) {
  if (!validateSelectEnvelope(body)) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }

  const record = freezeStore.get(body.freezeId);
  const frozenResponse = record ? record.response : null;

  const candidateNames = body.candidates.map(c => c && c.name).filter(n => isNonEmptyStr(n));
  const policyInvalid = validatePolicy(body.policy, candidateNames);

  // must exactly equal what was stored for this freezeId
  const lineageOk = !!frozenResponse && deepEqual(frozenResponse.candidates, body.candidates);

  const results = [];
  let winner = null;

  // Always iterate over the REAL submitted candidate names, never a name
  // that only appears in a (possibly broken) candidateOrder. Use
  // candidateOrder for sorting only when it's actually valid; otherwise
  // fall back to sorting the real names by UTF-8 bytes.
  const orderIsUsable = !policyInvalid && Array.isArray(body.policy.candidateOrder);
  const iterationOrder = orderIsUsable
    ? body.policy.candidateOrder
    : [...candidateNames].sort(utf8ByteCompare);

  for (const name of iterationOrder) {
    const reasonCodes = [];
    const frozenEntry = frozenResponse
      ? frozenResponse.candidates.find(c => c.name === name)
      : null;

    if (!lineageOk) reasonCodes.push("NOT_FROZEN");
    else if (!frozenEntry || frozenEntry.status !== "frozen") reasonCodes.push("INVALID_LINEAGE");

    if (policyInvalid) reasonCodes.push("INVALID_POLICY");

    // recompute manifest from OUR stored files, never trust submitted totals
    let totalBytes = null;
    let manifestOk = false;
    if (record && record.filesByName[name]) {
      const recomputed = computeManifest(record.filesByName[name]);
      manifestOk = frozenEntry && recomputed.packageDigest === frozenEntry.packageDigest;
      totalBytes = manifestOk ? recomputed.totalBytes : null;
      if (!manifestOk) reasonCodes.push("INVALID_MANIFEST");
    } else {
      reasonCodes.push("INVALID_MANIFEST");
    }

    const { aggregate, slices, valid: predsValid } = computeAccuracy(body.rows, name);
    if (!predsValid) reasonCodes.push("INVALID_PREDICTIONS");

    if (predsValid && !policyInvalid) {
      if (aggregate < body.policy.aggregateFloor) reasonCodes.push("AGGREGATE_FLOOR");
      for (const sliceName of Object.keys(body.policy.requiredSlices || {})) {
        if (!(sliceName in slices)) {
          reasonCodes.push(`MISSING_SLICE:${sliceName}`);
        } else if (slices[sliceName] < body.policy.requiredSlices[sliceName]) {
          reasonCodes.push(`SLICE_FLOOR:${sliceName}`);
        }
      }
    }

    if (totalBytes === null || totalBytes > body.policy.maxBytes) {
      reasonCodes.push("SIZE_LIMIT");
    }

    const latencyMs = isFiniteNumber(body.latencies && body.latencies[name]) && body.latencies[name] >= 0
      ? body.latencies[name]
      : null;
    if (latencyMs === null || (!policyInvalid && latencyMs > body.policy.maxLatencyMs)) {
      reasonCodes.push("LATENCY_LIMIT");
    }

    const admitted = reasonCodes.length === 0;

    const entry = {
      name,
      aggregate: predsValid ? aggregate : null,
      slices: predsValid ? slices : null,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes: dedupeSortCodes(reasonCodes),
    };
    results.push(entry);

    if (admitted) {
      const orderIdx = (body.policy.candidateOrder || []).indexOf(name);
      if (!winner ||
          entry.totalBytes < winner.entry.totalBytes ||
          (entry.totalBytes === winner.entry.totalBytes && entry.latencyMs < winner.entry.latencyMs) ||
          (entry.totalBytes === winner.entry.totalBytes && entry.latencyMs === winner.entry.latencyMs && orderIdx < winner.orderIdx)) {
        winner = { entry, orderIdx };
      }
    }
  }

  const selected = winner ? winner.entry.name : null;
  const packageManifest = winner && frozenResponse
    ? frozenResponse.candidates.find(c => c.name === selected)
    : null;

  return res.status(200).json({
    freezeId: body.freezeId,
    selected,
    results,
    packageManifest,
  });
}

// ---------- routing ----------

app.post("/quantize", (req, res) => {
  const body = req.body;
  if (!body || typeof body !== "object") {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }
  if (body.phase === "freeze") return handleFreeze(body, res);
  if (body.phase === "select") return handleSelect(body, res);
  return res.status(400).json({ error: "INVALID_INPUT" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`quantize-api listening on port ${PORT}`));