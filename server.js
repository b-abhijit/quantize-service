const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "10mb" }));

// in-memory store: freezeId -> { requestBody, response }
const freezeStore = new Map();

// ---------- helpers ----------

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

// Compare two strings by their raw UTF-8 bytes (not locale-aware sort)
function compareUtf8(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return Buffer.compare(ba, bb);
}

function validateCandidateShape(candidate) {
  if (typeof candidate !== "object" || candidate === null) return false;
  if (!isNonEmptyString(candidate.name)) return false;

  const files = candidate.files;
  if (typeof files !== "object" || files === null) return false;
  const keys = Object.keys(files);
  if (keys.length === 0) return false;
  for (const k of keys) {
    if (typeof files[k] !== "string") return false;
  }

  // Optional fields, if present must be right type
  if ("loadable" in candidate && typeof candidate.loadable !== "boolean") return false;
  if ("calibrationDigest" in candidate && typeof candidate.calibrationDigest !== "string") return false;
  if ("tokenizerDigest" in candidate && typeof candidate.tokenizerDigest !== "string") return false;
  if ("unsupportedReason" in candidate && typeof candidate.unsupportedReason !== "string") return false;

  return true;
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
    if (names.has(c.name)) return false; // names must be unique
    names.add(c.name);
  }
  return true;
}

// Build sorted inventory + totalBytes for one candidate's files
function computeInventory(files) {
  const items = Object.keys(files).map((name) => {
    const bytes = Buffer.from(files[name], "utf8");
    return { name, bytes: bytes.length, sha256: sha256Hex(bytes) };
  });
  items.sort((a, b) => compareUtf8(a.name, b.name));
  const totalBytes = items.reduce((sum, i) => sum + i.bytes, 0);
  return { inventory: items, totalBytes };
}

// packageDigest = sha256(utf8(compact JSON of inventory, keys in order name,bytes,sha256))
function computePackageDigest(inventory) {
  const ordered = inventory.map((i) => ({ name: i.name, bytes: i.bytes, sha256: i.sha256 }));
  const jsonStr = JSON.stringify(ordered); // compact by default
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
    const { inventory, totalBytes } = computeInventory(candidate.files);
    const packageDigest = computePackageDigest(inventory);
    const { status, reasonCodes } = decideCandidateStatus(candidate, body);

    return {
      name: candidate.name,
      status,
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes,
    };
  });

  results.sort((a, b) => compareUtf8(a.name, b.name));

  return {
    freezeId: body.freezeId,
    candidates: results,
  };
}

// Simple deep equality for detecting "identical replay" vs "conflict"
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

// ---------- route handlers ----------

function handleFreeze(body, res) {
  if (!validateFreezeRequest(body)) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }

  const existing = freezeStore.get(body.freezeId);

  if (existing) {
    if (deepEqual(existing.requestBody, body)) {
      return res.status(200).json(existing.response);
    } else {
      return res.status(409).json({ error: "FREEZE_ID_CONFLICT" });
    }
  }

  const response = buildFreezeResponse(body);
  freezeStore.set(body.freezeId, { requestBody: body, response });
  return res.status(200).json(response);
}

function handleSelect(body, res) {
  // TODO: implement Steps 7–13 from the guide
  return res.status(400).json({ error: "INVALID_INPUT" });
}

// ---------- express app wiring ----------

app.post("/quantize", (req, res) => {
  const body = req.body;

  if (body?.phase === "freeze") {
    return handleFreeze(body, res);
  } else if (body?.phase === "select") {
    return handleSelect(body, res);
  } else {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on port ${PORT}`));