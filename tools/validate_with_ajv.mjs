import fs from "node:fs";
import process from "node:process";
import Ajv from "ajv";

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, "utf8"));
}

function resolveLocalRef(root, ref) {
  if (typeof ref !== "string" || !ref.startsWith("#/")) return null;
  const parts = ref.slice(2).split("/").map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
  let node = root;
  for (const part of parts) {
    if (!node || typeof node !== "object" || !(part in node)) return null;
    node = node[part];
  }
  return node;
}

/**
 * Implement the project-defined "merged-object semantics" for `allOf`:
 * - Resolve local "#/..." $refs inside allOf.
 * - When all subschemas are object schemas (after deref), merge their properties
 *   and required sets into a single object schema, preserving additionalProperties.
 *
 * This operates on an in-memory copy of the frozen schema.
 */
function mergeAllOfObjects(node, root) {
  if (!node || typeof node !== "object") return node;
  if (Array.isArray(node)) return node.map((v) => mergeAllOfObjects(v, root));

  const out = {};
  for (const [k, v] of Object.entries(node)) {
    out[k] = mergeAllOfObjects(v, root);
  }

  if (!Array.isArray(out.allOf)) return out;

  // Expand local $refs within allOf.
  const expandedSubs = out.allOf.map((s) => {
    if (s && typeof s === "object" && "$ref" in s) {
      const resolved = resolveLocalRef(root, s.$ref);
      if (resolved) {
        return mergeAllOfObjects(resolved, root);
      }
    }
    return mergeAllOfObjects(s, root);
  });

  const canMerge = expandedSubs.every(
    (s) =>
      s &&
      typeof s === "object" &&
      !Array.isArray(s) &&
      (s.type === undefined || s.type === "object")
  );
  if (!canMerge) {
    out.allOf = expandedSubs;
    return out;
  }

  const merged = { ...out };
  delete merged.allOf;

  const mergedProps = { ...(merged.properties || {}) };
  const mergedReq = new Set(Array.isArray(merged.required) ? merged.required : []);

  for (const s of expandedSubs) {
    if (s.properties && typeof s.properties === "object") {
      for (const [pk, pv] of Object.entries(s.properties)) {
        mergedProps[pk] = pv;
      }
    }
    if (Array.isArray(s.required)) {
      for (const r of s.required) mergedReq.add(r);
    }
  }

  merged.properties = mergedProps;
  if (mergedReq.size > 0) merged.required = Array.from(mergedReq);

  const apFalse =
    expandedSubs.some((s) => s.additionalProperties === false) ||
    merged.additionalProperties === false;
  if (apFalse) merged.additionalProperties = false;

  return merged;
}

function main() {
  const [schemaPath, instancePath] = process.argv.slice(2);
  if (!schemaPath || !instancePath) {
    console.error("Usage: node tools/validate_with_ajv.mjs <schema.json> <instance.json>");
    process.exit(2);
  }

  const original = readJson(schemaPath);
  const schema = mergeAllOfObjects(original, original);
  const instance = readJson(instancePath);

  // Authoritative project settings (per user instruction):
  // - ajv@8.x
  // - strict: false
  // - allErrors: true
  const ajv = new Ajv({ strict: false, allErrors: true });
  const validate = ajv.compile(schema);

  const ok = validate(instance);
  if (!ok) {
    console.error(JSON.stringify({ valid: false, errors: validate.errors }, null, 2));
    process.exit(1);
  }
  process.stdout.write(JSON.stringify({ valid: true }, null, 2));
}

main();

