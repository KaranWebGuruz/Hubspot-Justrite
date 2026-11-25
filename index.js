import "dotenv/config";
import express from "express";
import { timingSafeEqual } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const app = express();
app.disable("x-powered-by");
// Raised from 1mb so templates and base64 images fit in one request.
app.use(express.json({ limit: "15mb" }));

const PORT = Number(process.env.PORT || 3000);
const HUBSPOT_TOKEN = process.env.HUBSPOT_ACCESS_TOKEN;
const MCP_ACCESS_KEY = process.env.MCP_ACCESS_KEY;
// Set WRITE_ENABLED=false on Render to switch every write tool off without a redeploy of code.
const WRITE_ENABLED = process.env.WRITE_ENABLED !== "false";
const HUBSPOT_API = "https://api.hubapi.com";
// HubSpot Reporting API (public beta). Change here if HubSpot releases a newer version.
const REPORTING = "/analytics/reporting/2027-03-beta";

if (!HUBSPOT_TOKEN || !MCP_ACCESS_KEY) {
  console.error("Missing HUBSPOT_ACCESS_TOKEN or MCP_ACCESS_KEY in your .env file.");
  process.exit(1);
}

function isAuthorized(req) {
  const supplied = Buffer.from(req.get("x-api-key") || "");
  const expected = Buffer.from(MCP_ACCESS_KEY);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function requireAuth(req, res, next) {
  if (!isAuthorized(req)) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function assertSafePath(path) {
  if (
    typeof path !== "string" ||
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("..") ||
    path.includes("\\") ||
    path.includes("?") ||
    path.includes("#")
  ) {
    throw new Error("Invalid HubSpot API path.");
  }
}

function buildUrl(path, query) {
  assertSafePath(path);
  const url = new URL(path, HUBSPOT_API);
  if (url.origin !== HUBSPOT_API) throw new Error("Only the official HubSpot API is permitted.");
  for (const [key, value] of Object.entries(query || {})) {
    if (Array.isArray(value)) value.forEach((v) => url.searchParams.append(key, String(v)));
    else if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
  }
  return url;
}

// Collects scope names HubSpot reports as missing (403 MISSING_SCOPES), wherever they appear in the body.
function collectMissingScopes(data) {
  const found = new Set();
  const visit = (ctx) => {
    if (!ctx || typeof ctx !== "object") return;
    for (const key of ["requiredGranularScopes", "requiredScopes", "missingScopes"]) {
      const v = ctx[key];
      if (Array.isArray(v)) v.forEach((s) => found.add(String(s)));
    }
  };
  visit(data.context);
  if (Array.isArray(data.errors)) data.errors.forEach((e) => visit(e?.context));
  return [...found];
}

async function parseResponse(response) {
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { message: text };
  }
  if (!response.ok) {
    // Return HubSpot's full error body so the caller can see category, field errors and missing scopes.
    // HubSpot error bodies never contain the access token.
    const missingScopes = collectMissingScopes(data);
    const detail = {
      status: response.status,
      ...(data.category ? { category: data.category } : {}),
      message: data.message || data.error || "Request failed",
      ...(missingScopes.length ? { missingScopes } : {}),
      ...(data.errors ? { errors: data.errors } : {}),
      ...(data.context ? { context: data.context } : {}),
      ...(data.correlationId ? { correlationId: data.correlationId } : {}),
    };
    let detailText = JSON.stringify(detail, null, 2);
    if (detailText.length > 8000) detailText = detailText.slice(0, 8000) + "\n[error body shortened]";
    const error = new Error(`HubSpot API returned HTTP ${response.status}: ${detail.message}\n${detailText}`);
    error.status = response.status;
    error.details = data;
    throw error;
  }
  // 204 No Content (e.g. deletes) comes back as {} — make it explicit.
  return text ? data : { success: true, status: response.status };
}

// ---------------------------------------------------------------- write audit log
// One JSON line per write call: time, tool, method, API path (holds the object ID), new object ID, status.
// Never logs headers, the token, the MCP key, query strings or request bodies (bodies can hold contact data).
const toolContext = new AsyncLocalStorage();

function isWriteCall(method, path) {
  return method !== "GET" && !path.endsWith("/search") && !path.endsWith("/batch/read");
}

function logWrite(method, path, status, data) {
  if (!isWriteCall(method, path)) return;
  const objectId = data && (data.id || data.listId || data.list?.listId || data.flowId || data.name);
  console.log(
    JSON.stringify({
      event: "hubspot_write",
      time: new Date().toISOString(),
      tool: toolContext.getStore()?.tool || "unknown",
      method,
      path,
      ...(objectId ? { objectId: String(objectId) } : {}),
      status,
    })
  );
}

async function sendLogged(path, method, init) {
  try {
    const response = await fetch(buildUrl(path, init.query), { method, ...init.fetchOptions });
    const data = await parseResponse(response);
    logWrite(method, path, response.status, data);
    return data;
  } catch (error) {
    logWrite(method, path, error.status || "request_failed", null);
    throw error;
  }
}

// JSON requests. Query strings go in options.query.
async function hubspotRequest(path, options = {}) {
  return sendLogged(path, options.method || "GET", {
    query: options.query,
    fetchOptions: {
      headers: {
        Authorization: `Bearer ${HUBSPOT_TOKEN}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      signal: AbortSignal.timeout(30000),
    },
  });
}

// Multipart requests (file uploads, CMS source code).
async function hubspotMultipart(path, formData, method = "POST") {
  return sendLogged(path, method, {
    fetchOptions: {
      headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}`, Accept: "application/json" },
      body: formData,
      signal: AbortSignal.timeout(60000),
    },
  });
}

function output(data) {
  const json = JSON.stringify(data, null, 2);
  const maxLength = 25000;
  return {
    content: [
      {
        type: "text",
        text:
          json.length > maxLength
            ? json.slice(0, maxLength) + "\n\n[Output shortened. Narrow your search or request fewer fields.]"
            : json,
      },
    ],
  };
}

function requireWrite() {
  if (!WRITE_ENABLED) throw new Error("Write tools are disabled on this server (WRITE_ENABLED=false).");
}

const ID = /^[a-zA-Z0-9_-]+$/;
function assertId(value, label = "parameter") {
  if (!ID.test(value)) throw new Error(`Invalid ${label}.`);
}

// Encodes each segment of a design-manager path like "custom/emails/jsg-quote.html".
function encodeCmsPath(filePath) {
  const clean = filePath.replace(/^\/+/, "");
  if (!clean || clean.includes("..") || clean.includes("\\")) throw new Error("Invalid file path.");
  return clean.split("/").map(encodeURIComponent).join("/");
}

// Fields HubSpot returns on GET of a v4 flow that must not be sent back on PUT.
const FLOW_READ_ONLY_FIELDS = ["id", "createdAt", "updatedAt", "crmObjectCreationStatus"];

async function getFlow(flowId) {
  assertId(flowId, "flow ID");
  return hubspotRequest(`/automation/v4/flows/${encodeURIComponent(flowId)}`);
}

// Builds a valid PUT body: current flow + your changes, always with the latest revisionId.
function mergeFlow(current, changes) {
  const merged = { ...current, ...changes, revisionId: current.revisionId };
  for (const f of FLOW_READ_ONLY_FIELDS) delete merged[f];
  return merged;
}

// Reads one list (segment). Lists v3 wraps the result in { list: {...} }.
async function getList(listId, includeFilters = true) {
  assertId(listId, "list ID");
  const data = await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}`, {
    query: { includeFilters: String(includeFilters) },
  });
  return data.list || data;
}

const queryParamsSchema = z
  .record(z.string(), z.union([z.string(), z.array(z.string())]))
  .optional()
  .describe("Query parameters. Use an array for repeated params, e.g. { properties: ['tags', 'permissions'] }");

const filterBranchSchema = z
  .record(z.string(), z.any())
  .describe(
    "HubSpot v3 lists filterBranch, passed to HubSpot unchanged (any valid v3 filter type works). " +
      "Root: { filterBranchType: 'OR', filterBranchOperator: 'OR', filters: [], filterBranches: [ { filterBranchType: 'AND', filterBranchOperator: 'AND', filters: [...], filterBranches: [] } ] }. " +
      "Each AND branch is one group of conditions; the OR root means a record matches if any group matches. " +
      "Filter examples: " +
      "Brand = Justrite: { filterType: 'PROPERTY', property: 'hs_all_assigned_business_unit_ids', operation: { operationType: 'ENUMERATION', operator: 'IS_ANY_OF', values: ['0'], includeObjectsWithNoValueSet: false } }. " +
      "In another list: { filterType: 'IN_LIST', listId: '123', operator: 'IN_LIST' }; not in a list: same with operator 'NOT_IN_LIST'. " +
      "Relative date range (e.g. last email open 180-90 days ago): { filterType: 'PROPERTY', property: 'hs_email_last_open_date', operation: { operationType: 'TIME_RANGED', operator: 'IS_BETWEEN', includeObjectsWithNoValueSet: false, " +
      "lowerBoundTimePoint: { timeType: 'INDEXED', timezoneSource: 'CUSTOM', zoneId: 'US/Eastern', indexReference: { referenceType: 'TODAY' }, offset: { days: -180 } }, " +
      "upperBoundTimePoint: { timeType: 'INDEXED', timezoneSource: 'CUSTOM', zoneId: 'US/Eastern', indexReference: { referenceType: 'TODAY' }, offset: { days: -90 } } } }. " +
      "If HubSpot rejects a shape, read an existing list that uses the same filter with get_list and copy it exactly."
  );

const PROPERTY_TYPES = ["string", "number", "date", "datetime", "enumeration", "bool"];
const PROPERTY_FIELD_TYPES = [
  "text",
  "textarea",
  "date",
  "file",
  "number",
  "select",
  "radio",
  "checkbox",
  "booleancheckbox",
  "calculation_equation",
  "html",
  "phonenumber",
];
const propertyOptionSchema = z.object({
  label: z.string().min(1),
  value: z.string().min(1),
  description: z.string().optional(),
  displayOrder: z.number().int().optional(),
  hidden: z.boolean().optional(),
});

function registerTools(server) {
  // Run every tool handler inside a context that carries the tool name, so the write log can record it.
  const baseRegister = server.registerTool.bind(server);
  server.registerTool = (name, config, handler) =>
    baseRegister(name, config, (...args) => toolContext.run({ tool: name }, () => handler(...args)));

  // ================================================================ READ TOOLS

  server.registerTool(
    "hubspot_portal_info",
    { description: "Check the connected HubSpot account and portal information.", inputSchema: {} },
    async () => output(await hubspotRequest("/account-info/v3/details"))
  );

  server.registerTool(
    "search_crm_records",
    {
      description:
        "Search HubSpot CRM records by text. Supports contacts, companies, deals, tickets and custom object type IDs. Optionally sort and filter.",
      inputSchema: {
        objectType: z.string().min(1).describe("e.g. contacts, companies, deals, tickets, or a custom object type ID."),
        query: z.string().optional().describe("Text to search for. Leave empty to retrieve records."),
        properties: z.array(z.string()).max(50).optional(),
        filterGroups: z.array(z.any()).optional().describe("HubSpot search filterGroups array, passed through as-is."),
        sorts: z
          .array(z.object({ propertyName: z.string(), direction: z.enum(["ASCENDING", "DESCENDING"]) }))
          .optional()
          .describe("e.g. [{ propertyName: 'createdate', direction: 'DESCENDING' }]"),
        limit: z.number().int().min(1).max(100).optional(),
        after: z.string().optional(),
      },
    },
    async ({ objectType, query, properties, filterGroups, sorts, limit, after }) => {
      const type = objectType.trim();
      assertId(type, "CRM object type");
      const body = {
        limit: limit || 10,
        ...(query ? { query } : {}),
        ...(properties?.length ? { properties } : {}),
        ...(filterGroups?.length ? { filterGroups } : {}),
        ...(sorts?.length ? { sorts } : {}),
        ...(after ? { after } : {}),
      };
      return output(await hubspotRequest(`/crm/v3/objects/${encodeURIComponent(type)}/search`, { method: "POST", body }));
    }
  );

  server.registerTool(
    "get_crm_record",
    {
      description: "Retrieve one HubSpot CRM record by object type and record ID.",
      inputSchema: {
        objectType: z.string().min(1),
        recordId: z.string().min(1),
        properties: z.array(z.string()).max(50).optional(),
      },
    },
    async ({ objectType, recordId, properties }) => {
      assertId(objectType, "object type");
      assertId(recordId, "record ID");
      return output(
        await hubspotRequest(`/crm/v3/objects/${encodeURIComponent(objectType)}/${encodeURIComponent(recordId)}`, {
          query: { properties: properties || [] },
        })
      );
    }
  );

  server.registerTool(
    "list_object_properties",
    {
      description: "List HubSpot CRM properties for a standard or custom object.",
      inputSchema: { objectType: z.string().min(1) },
    },
    async ({ objectType }) => {
      assertId(objectType, "object type");
      return output(await hubspotRequest(`/crm/v3/properties/${encodeURIComponent(objectType)}`));
    }
  );

  server.registerTool(
    "get_crm_associations",
    {
      description: "Retrieve associations from a HubSpot record to records of another object type.",
      inputSchema: {
        fromObjectType: z.string().min(1),
        recordId: z.string().min(1),
        toObjectType: z.string().min(1),
        after: z.string().optional(),
        limit: z.number().int().min(1).max(500).optional(),
      },
    },
    async ({ fromObjectType, recordId, toObjectType, after, limit }) => {
      [fromObjectType, recordId, toObjectType].forEach((v) => assertId(v, "association parameter"));
      return output(
        await hubspotRequest(
          `/crm/v4/objects/${encodeURIComponent(fromObjectType)}/${encodeURIComponent(recordId)}/associations/${encodeURIComponent(toObjectType)}`,
          { query: { limit: limit || 100, after } }
        )
      );
    }
  );

  server.registerTool(
    "list_crm_pipelines",
    {
      description: "List pipelines and stages for a HubSpot CRM object, such as deals or tickets.",
      inputSchema: { objectType: z.string().min(1) },
    },
    async ({ objectType }) => {
      assertId(objectType, "object type");
      return output(await hubspotRequest(`/crm/v3/pipelines/${encodeURIComponent(objectType)}`));
    }
  );

  server.registerTool(
    "read_hubspot_api",
    {
      description:
        "Read-only GET request to a supported HubSpot API endpoint (CRM, lists, forms, workflows, sequences, CMS, marketing, files, analytics, reporting). Path must start with /. Put query parameters in queryParams.",
      inputSchema: {
        path: z.string().min(1).describe("Relative path, e.g. /marketing/v3/emails"),
        queryParams: queryParamsSchema,
      },
    },
    async ({ path, queryParams }) => {
      const allowedPrefixes = [
        "/account-info/v3/",
        "/crm/v3/objects/",
        "/crm/v4/objects/",
        "/crm/v3/properties/",
        "/crm/v3/pipelines/",
        "/crm/v3/lists",
        "/crm/v3/owners",
        "/crm/v3/schemas",
        "/forms/v2/forms",
        "/marketing/v3/forms",
        "/form-integrations/v1/submissions/forms/",
        "/automation/v4/flows",
        "/automation/v4/sequences",
        "/analytics/v2/",
        "/analytics/reporting/",
        "/events/v3/",
        "/cms/v3/",
        "/content/api/v2/templates",
        "/marketing/v3/",
        "/communication-preferences/v3/",
        "/files/v3/",
        "/settings/v3/users",
      ];
      if (!allowedPrefixes.some((p) => path.startsWith(p))) {
        throw new Error("This API path is not allowed by the read-only endpoint policy.");
      }
      return output(await hubspotRequest(path, { query: queryParams }));
    }
  );

  // ================================================================ LISTS / SEGMENTS (Lists v3)
  // Private app scopes needed: crm.lists.read (read tools) and crm.lists.write (write tools).

  server.registerTool(
    "search_lists",
    {
      description: "Search lists (segments) by name. Read-only. Returns list IDs, names, type and size.",
      inputSchema: {
        query: z.string().optional().describe("Text in the list name, e.g. 'Spill Kits'."),
        processingTypes: z.array(z.enum(["MANUAL", "DYNAMIC", "SNAPSHOT"])).optional(),
        count: z.number().int().min(1).max(500).optional().describe("Default 25."),
        offset: z.number().int().min(0).optional(),
      },
    },
    async ({ query, processingTypes, count, offset }) =>
      output(
        await hubspotRequest("/crm/v3/lists/search", {
          method: "POST",
          body: {
            ...(query ? { query } : {}),
            ...(processingTypes?.length ? { processingTypes } : {}),
            count: count || 25,
            offset: offset || 0,
          },
        })
      )
  );

  server.registerTool(
    "get_list",
    {
      description: "Get one list (segment) with its filter definition (filterBranch), type and size. Read this before update_list_filters.",
      inputSchema: {
        listId: z.string().min(1),
        includeFilters: z.boolean().optional().describe("Default true."),
      },
    },
    async ({ listId, includeFilters }) => output(await getList(listId, includeFilters !== false))
  );

  server.registerTool(
    "get_list_memberships",
    {
      description: "Page through the record IDs that are members of a list. Read-only.",
      inputSchema: {
        listId: z.string().min(1),
        limit: z.number().int().min(1).max(250).optional().describe("Default 100."),
        after: z.string().optional(),
      },
    },
    async ({ listId, limit, after }) => {
      assertId(listId, "list ID");
      return output(
        await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}/memberships`, {
          query: { limit: limit || 100, after },
        })
      );
    }
  );

  server.registerTool(
    "create_list",
    {
      description:
        "Create a list (segment). processingType MANUAL = static, DYNAMIC = active with filterBranch. objectTypeId: 0-1 contacts, 0-2 companies, 0-3 deals.",
      inputSchema: {
        name: z.string().min(1),
        objectTypeId: z.string().min(1),
        processingType: z.enum(["MANUAL", "DYNAMIC", "SNAPSHOT"]),
        filterBranch: filterBranchSchema.optional().describe("Required for DYNAMIC lists."),
        listFolderId: z.number().int().optional().describe("Optional folder to create the list in."),
      },
    },
    async ({ name, objectTypeId, processingType, filterBranch, listFolderId }) => {
      requireWrite();
      if (processingType === "DYNAMIC" && !filterBranch) throw new Error("DYNAMIC lists need a filterBranch.");
      return output(
        await hubspotRequest("/crm/v3/lists", {
          method: "POST",
          body: {
            name,
            objectTypeId,
            processingType,
            ...(filterBranch ? { filterBranch } : {}),
            ...(listFolderId !== undefined ? { listFolderId } : {}),
          },
        })
      );
    }
  );

  server.registerTool(
    "update_list_filters",
    {
      description:
        "Replace the filters of an existing ACTIVE (DYNAMIC) list, keeping the same list ID so emails and reports that use it keep working. Sends the full new filterBranch (not a partial change). Returns the previous filterBranch so the change can be reverted. Confirm the new filters with the user before calling.",
      inputSchema: {
        listId: z.string().min(1),
        filterBranch: filterBranchSchema,
        enrollObjectsInWorkflows: z
          .boolean()
          .optional()
          .describe(
            "Default false. If true, records newly added by the change can enroll in workflows that use this list. Requires confirm: true."
          ),
        confirm: z
          .boolean()
          .optional()
          .describe("Must be true when enrollObjectsInWorkflows is true. Only set after the user has explicitly confirmed."),
      },
    },
    async ({ listId, filterBranch, enrollObjectsInWorkflows, confirm }) => {
      requireWrite();
      if (enrollObjectsInWorkflows && confirm !== true) {
        throw new Error("enrollObjectsInWorkflows: true enrolls records in workflows. Pass confirm: true after the user confirms.");
      }
      const current = await getList(listId, true);
      if (current.processingType !== "DYNAMIC") {
        throw new Error(`List ${listId} is ${current.processingType}. Only DYNAMIC (active) lists have editable filters.`);
      }
      const result = await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}/update-list-filters`, {
        method: "PUT",
        query: { enrollObjectsInWorkflows: String(Boolean(enrollObjectsInWorkflows)) },
        body: { filterBranch },
      });
      return output({ listId, name: current.name, previousFilterBranch: current.filterBranch, result });
    }
  );

  server.registerTool(
    "rename_list",
    {
      description: "Rename an existing list (segment).",
      inputSchema: { listId: z.string().min(1), name: z.string().min(1) },
    },
    async ({ listId, name }) => {
      requireWrite();
      assertId(listId, "list ID");
      return output(
        await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}/update-list-name`, {
          method: "PUT",
          query: { listName: name, includeFilters: "false" },
        })
      );
    }
  );

  server.registerTool(
    "add_to_list",
    {
      description: "Add record IDs to a static (MANUAL) list.",
      inputSchema: { listId: z.string().min(1), recordIds: z.array(z.string()).min(1).max(1000) },
    },
    async ({ listId, recordIds }) => {
      requireWrite();
      assertId(listId, "list ID");
      return output(
        await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}/memberships/add`, { method: "PUT", body: recordIds })
      );
    }
  );

  server.registerTool(
    "remove_from_list",
    {
      description: "Remove record IDs from a static (MANUAL) list.",
      inputSchema: { listId: z.string().min(1), recordIds: z.array(z.string()).min(1).max(1000) },
    },
    async ({ listId, recordIds }) => {
      requireWrite();
      assertId(listId, "list ID");
      return output(
        await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}/memberships/remove`, { method: "PUT", body: recordIds })
      );
    }
  );

  server.registerTool(
    "delete_list",
    {
      description:
        "Delete a list (segment). HubSpot keeps it restorable for 90 days (see restore_list). Emails and workflows using the list will lose it. Requires confirm: true; only use after the user has explicitly confirmed.",
      inputSchema: { listId: z.string().min(1), confirm: z.literal(true) },
    },
    async ({ listId }) => {
      requireWrite();
      assertId(listId, "list ID");
      return output(await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}`, { method: "DELETE" }));
    }
  );

  server.registerTool(
    "restore_list",
    {
      description: "Restore a list that was deleted in the last 90 days.",
      inputSchema: { listId: z.string().min(1) },
    },
    async ({ listId }) => {
      requireWrite();
      assertId(listId, "list ID");
      return output(await hubspotRequest(`/crm/v3/lists/${encodeURIComponent(listId)}/restore`, { method: "PUT" }));
    }
  );

  // ================================================================ CONTACT PROPERTIES & SUBSCRIPTIONS
  // Scopes: crm.schemas.contacts.read / crm.schemas.contacts.write, communication_preferences.read.

  server.registerTool(
    "create_contact_property",
    {
      description:
        "Create a contact property. Idempotent: if a property with this name already exists, returns it (created: false) instead of failing. " +
        "type/fieldType pairs: string+text|textarea|html|phonenumber, number+number, date+date, datetime+date, bool+booleancheckbox, enumeration+select|radio|checkbox. " +
        "enumeration needs options; bool gets Yes/No options automatically.",
      inputSchema: {
        name: z
          .string()
          .regex(/^[a-z][a-z0-9_]*$/, "Lowercase letters, digits and underscores, starting with a letter.")
          .describe("Internal name, e.g. jr_reengagement_status"),
        label: z.string().min(1),
        type: z.enum(PROPERTY_TYPES),
        fieldType: z.enum(PROPERTY_FIELD_TYPES),
        groupName: z.string().min(1).describe("Property group, e.g. contactinformation"),
        options: z.array(propertyOptionSchema).optional(),
        description: z.string().optional(),
        extra: z.record(z.string(), z.any()).optional().describe("Other v3 property fields, e.g. { formField: true, hasUniqueValue: false }"),
      },
    },
    async ({ name, label, type, fieldType, groupName, options, description, extra }) => {
      requireWrite();
      let opts = options;
      if (type === "bool" && !opts?.length) {
        opts = [
          { label: "Yes", value: "true", displayOrder: 0 },
          { label: "No", value: "false", displayOrder: 1 },
        ];
      }
      if (type === "enumeration" && !opts?.length) throw new Error("enumeration properties need options.");
      const body = {
        name,
        label,
        type,
        fieldType,
        groupName,
        ...(opts?.length ? { options: opts } : {}),
        ...(description ? { description } : {}),
        ...(extra || {}),
      };
      try {
        const property = await hubspotRequest("/crm/v3/properties/contacts", { method: "POST", body });
        return output({ created: true, property });
      } catch (error) {
        if (error.status !== 409) throw error;
        const property = await hubspotRequest(`/crm/v3/properties/contacts/${encodeURIComponent(name)}`);
        return output({ created: false, note: "Property already existed; returned unchanged.", property });
      }
    }
  );

  server.registerTool(
    "update_contact_property",
    {
      description:
        "Update an existing contact property (PATCH). Only the fields you pass change, e.g. { label, description, groupName, options }. Sending options REPLACES the full option list, so include existing options you want to keep (read them with read_hubspot_api /crm/v3/properties/contacts/{name}).",
      inputSchema: {
        name: z.string().min(1),
        fields: z.record(z.string(), z.any()),
      },
    },
    async ({ name, fields }) => {
      requireWrite();
      assertId(name, "property name");
      return output(
        await hubspotRequest(`/crm/v3/properties/contacts/${encodeURIComponent(name)}`, { method: "PATCH", body: fields })
      );
    }
  );

  server.registerTool(
    "get_subscription_definitions",
    {
      description:
        "Read-only. List email subscription types (id, name, description, business unit) so you can see which subscription type an email sends under (compare with the email's subscriptionDetails.subscriptionId).",
      inputSchema: {},
    },
    async () => output(await hubspotRequest("/communication-preferences/v3/definitions"))
  );

  // ================================================================ WORKFLOWS (Automation v4)

  server.registerTool(
    "list_workflows",
    {
      description: "List workflows (Automation v4): id, name, type, enabled status, revisionId. Paginate with after.",
      inputSchema: {
        limit: z.number().int().min(1).max(100).optional(),
        after: z.string().optional(),
      },
    },
    async ({ limit, after }) =>
      output(await hubspotRequest("/automation/v4/flows", { query: { limit: limit || 100, after } }))
  );

  server.registerTool(
    "get_workflow",
    {
      description:
        "Get the full definition of one workflow: enrollment criteria, actions, revisionId, isEnabled. Read this before updating a workflow.",
      inputSchema: { flowId: z.string().min(1) },
    },
    async ({ flowId }) => output(await getFlow(flowId))
  );

  server.registerTool(
    "create_workflow",
    {
      description:
        "Create a workflow with the Automation v4 flows API. Pass the full flow definition; it is sent to HubSpot unchanged (branches, delays, set-property, create-task and any other v4 actions are supported). Always created switched OFF (isEnabled: false) so it can be reviewed in HubSpot first. " +
        "Shape: { type: 'CONTACT_FLOW', objectTypeId: '0-1', flowType: 'WORKFLOW', name, startActionId: '1', nextAvailableActionId: '<n>', enrollmentCriteria: { type: 'LIST_BASED', shouldReEnroll: false, listFilterBranch: <v3 filterBranch>, unEnrollObjectsNotMeetingCriteria: false, reEnrollmentTriggersFilterBranches: [] }, actions: [...] }. " +
        "Each action has actionId, actionTypeVersion: 0, actionTypeId, fields, and either connection: { edgeType: 'STANDARD', nextActionId } or is last. Common actionTypeIds: '0-1' delay (fields { delta: '1440', time_unit: 'MINUTES' }), '0-3' create task, '0-5' set property (fields { property_name, value: { type: 'STATIC_VALUE', staticValue } }). " +
        "Branches use type 'LIST_BRANCH' (listBranches: [{ filterBranch, connection }], defaultBranch) or 'STATIC_BRANCH'. " +
        "To get exact field names, read a similar existing workflow with get_workflow and copy its action shapes.",
      inputSchema: { flow: z.record(z.string(), z.any()).describe("Full v4 flow JSON body.") },
    },
    async ({ flow }) => {
      requireWrite();
      return output(await hubspotRequest("/automation/v4/flows", { method: "POST", body: { ...flow, isEnabled: false } }));
    }
  );

  server.registerTool(
    "update_workflow",
    {
      description:
        "Update an existing workflow (v4). Pass only the fields you want to change (e.g. name, actions, enrollmentCriteria); the server fetches the current workflow, merges your changes and sends the latest revisionId automatically. Does not change isEnabled unless you include it.",
      inputSchema: {
        flowId: z.string().min(1),
        changes: z.record(z.string(), z.any()).describe("v4 flow fields to change."),
      },
    },
    async ({ flowId, changes }) => {
      requireWrite();
      const current = await getFlow(flowId);
      return output(
        await hubspotRequest(`/automation/v4/flows/${encodeURIComponent(flowId)}`, {
          method: "PUT",
          body: mergeFlow(current, changes),
        })
      );
    }
  );

  server.registerTool(
    "set_workflow_enabled",
    {
      description:
        "Turn a workflow OFF (default) or ON. Turning ON starts enrolling records and can send emails, so it requires enabled: true AND confirm: true, only after the user has explicitly confirmed.",
      inputSchema: {
        flowId: z.string().min(1),
        enabled: z.boolean().optional().describe("Default false (turn OFF). true turns the workflow ON."),
        confirm: z.boolean().optional().describe("Required (true) to turn a workflow ON."),
      },
    },
    async ({ flowId, enabled, confirm }) => {
      requireWrite();
      const turnOn = enabled === true;
      if (turnOn && confirm !== true) {
        throw new Error("Turning a workflow ON enrolls records. Pass enabled: true and confirm: true after the user confirms.");
      }
      const current = await getFlow(flowId);
      return output(
        await hubspotRequest(`/automation/v4/flows/${encodeURIComponent(flowId)}`, {
          method: "PUT",
          body: mergeFlow(current, { isEnabled: turnOn }),
        })
      );
    }
  );

  server.registerTool(
    "delete_workflow",
    {
      description:
        "Permanently delete a workflow. Cannot be undone from the API. Requires confirm: true; only use after the user has explicitly confirmed.",
      inputSchema: { flowId: z.string().min(1), confirm: z.literal(true) },
    },
    async ({ flowId }) => {
      requireWrite();
      assertId(flowId, "flow ID");
      return output(await hubspotRequest(`/automation/v4/flows/${encodeURIComponent(flowId)}`, { method: "DELETE" }));
    }
  );

  // ================================================================ REPORTS & DASHBOARDS (Reporting API beta)
  // Manages report/dashboard METADATA only. HubSpot's API does not let you create a report from
  // scratch or change a report's configuration (filters, chart, data source). Workarounds:
  //   1. clone_reporting_object to copy a similar report, then rename it.
  //   2. Build reports in HubSpot that filter on LIST MEMBERSHIP or a CAMPAIGN. Changing the list
  //      with update_list_filters (or the campaign's assets) then changes what the report shows.
  // Export is not included because it needs a user-level app; private app tokens are account-level.

  const reportingKind = z.enum(["reports", "dashboards"]).describe("reports or dashboards");
  const permissionsSchema = z
    .record(z.string(), z.any())
    .describe("e.g. { permissionType: 'PRIVATE' | 'EVERYONE_VIEW' | 'EVERYONE_EDIT' | 'SPECIFIC', specificPermissions: [...] }");

  server.registerTool(
    "search_reporting_objects",
    {
      description:
        "Search HubSpot reports or dashboards. Optional queryParams: q (name text), ids, ownerUserIds, tagIds, businessUnitIds, dashboardId (reports only), onDashboard (reports only), sort (name | updatedAt | lastViewedAt, prefix - for descending), limit (max 100), after, properties (tags, widgets, permissions), archived.",
      inputSchema: { kind: reportingKind, queryParams: queryParamsSchema },
    },
    async ({ kind, queryParams }) => output(await hubspotRequest(`${REPORTING}/${kind}`, { query: queryParams }))
  );

  server.registerTool(
    "get_reporting_object",
    {
      description: "Retrieve one report or dashboard by ID. properties can include tags, widgets (dashboards only), permissions.",
      inputSchema: {
        kind: reportingKind,
        id: z.string().min(1),
        properties: z.array(z.enum(["tags", "widgets", "permissions"])).optional(),
        archived: z.boolean().optional(),
      },
    },
    async ({ kind, id, properties, archived }) => {
      assertId(id, "report/dashboard ID");
      return output(
        await hubspotRequest(`${REPORTING}/${kind}/${encodeURIComponent(id)}`, {
          query: { properties: properties || [], ...(archived ? { archived: "true" } : {}) },
        })
      );
    }
  );

  server.registerTool(
    "update_reporting_object",
    {
      description:
        "Update a report's or dashboard's metadata (PATCH): name, description, ownerUserId, permissions, businessUnitId. To archive or restore, send ONLY { archived: true | false }. Cannot change what a report measures or its filters.",
      inputSchema: {
        kind: reportingKind,
        id: z.string().min(1),
        changes: z.record(z.string(), z.any()).describe("e.g. { name: 'Weekly closed-won deals', ownerUserId: '11045285' }"),
      },
    },
    async ({ kind, id, changes }) => {
      requireWrite();
      assertId(id, "report/dashboard ID");
      if ("archived" in changes && Object.keys(changes).length > 1) {
        throw new Error("When 'archived' is sent it must be the only field.");
      }
      return output(await hubspotRequest(`${REPORTING}/${kind}/${encodeURIComponent(id)}`, { method: "PATCH", body: changes }));
    }
  );

  server.registerTool(
    "create_dashboard",
    {
      description:
        "Create a new dashboard, optionally attaching existing reports (best-effort, max 50 per dashboard; check widgets in the response).",
      inputSchema: {
        name: z.string().min(1),
        permissions: permissionsSchema.optional().describe("Default: { permissionType: 'PRIVATE' }"),
        description: z.string().optional(),
        businessUnitId: z.string().optional(),
        reportIdsToAdd: z.array(z.string()).max(50).optional(),
      },
    },
    async ({ name, permissions, description, businessUnitId, reportIdsToAdd }) => {
      requireWrite();
      return output(
        await hubspotRequest(`${REPORTING}/dashboards`, {
          method: "POST",
          body: {
            name,
            permissions: permissions || { permissionType: "PRIVATE" },
            ...(description ? { description } : {}),
            ...(businessUnitId ? { businessUnitId } : {}),
            ...(reportIdsToAdd?.length ? { reportIdsToAdd } : {}),
          },
        })
      );
    }
  );

  server.registerTool(
    "clone_reporting_object",
    {
      description:
        "Clone an existing report or dashboard. This is the only way to get a 'new' report by API: clone a similar one, then rename it. For dashboards, cloneReports (default true) also copies the reports.",
      inputSchema: {
        kind: reportingKind,
        id: z.string().min(1).describe("ID of the report or dashboard to copy."),
        name: z.string().min(1),
        permissions: permissionsSchema.optional().describe("Default: { permissionType: 'PRIVATE' }"),
        cloneReports: z.boolean().optional().describe("Dashboards only."),
      },
    },
    async ({ kind, id, name, permissions, cloneReports }) => {
      requireWrite();
      assertId(id, "report/dashboard ID");
      return output(
        await hubspotRequest(`${REPORTING}/${kind}/${encodeURIComponent(id)}/clone`, {
          method: "POST",
          body: {
            name,
            permissions: permissions || { permissionType: "PRIVATE" },
            ...(kind === "dashboards" && cloneReports !== undefined ? { cloneReports } : {}),
          },
        })
      );
    }
  );

  server.registerTool(
    "manage_dashboard_reports",
    {
      description: "Add reports to, or remove one report from, a dashboard (max 50 reports per dashboard).",
      inputSchema: {
        dashboardId: z.string().min(1),
        action: z.enum(["add", "remove"]),
        reportIds: z.array(z.string()).min(1).max(50).describe("For remove, pass exactly one ID."),
      },
    },
    async ({ dashboardId, action, reportIds }) => {
      requireWrite();
      assertId(dashboardId, "dashboard ID");
      reportIds.forEach((r) => assertId(r, "report ID"));
      const base = `${REPORTING}/dashboards/${encodeURIComponent(dashboardId)}`;
      if (action === "add") {
        return output(await hubspotRequest(`${base}/batch/widgets`, { method: "POST", body: { inputs: reportIds } }));
      }
      if (reportIds.length !== 1) throw new Error("Remove one report at a time.");
      return output(await hubspotRequest(`${base}/widgets/${encodeURIComponent(reportIds[0])}`, { method: "DELETE" }));
    }
  );

  server.registerTool(
    "batch_archive_reporting_objects",
    {
      description:
        "Archive (soft delete) or restore up to 500 reports or dashboards at once. Archived items are permanently purged after 90 days.",
      inputSchema: {
        kind: reportingKind,
        action: z.enum(["archive", "restore"]),
        ids: z.array(z.string()).min(1).max(500),
      },
    },
    async ({ kind, action, ids }) => {
      requireWrite();
      ids.forEach((i) => assertId(i, "report/dashboard ID"));
      return output(await hubspotRequest(`${REPORTING}/${kind}/batch/${action}`, { method: "POST", body: { inputs: ids } }));
    }
  );

  // ================================================================ CAMPAIGNS (Marketing Campaigns v3)
  // Private app scopes needed: marketing.campaigns.read and marketing.campaigns.write.
  // Read campaigns with read_hubspot_api, e.g. path /marketing/v3/campaigns.

  server.registerTool(
    "create_campaign",
    {
      description:
        "Create a marketing campaign. properties uses campaign property names, e.g. { hs_name: 'Justrite Spill Kits Launch', hs_start_date: '2026-11-17', hs_end_date: '2027-01-31', hs_notes: '...' }. Returns the campaign ID (a GUID) used by the other campaign tools.",
      inputSchema: { properties: z.record(z.string(), z.any()) },
    },
    async ({ properties }) => {
      requireWrite();
      if (!properties.hs_name) throw new Error("properties.hs_name (campaign name) is required.");
      return output(await hubspotRequest("/marketing/v3/campaigns", { method: "POST", body: { properties } }));
    }
  );

  server.registerTool(
    "update_campaign",
    {
      description: "Update a campaign's properties (PATCH). Only the properties you pass are changed.",
      inputSchema: {
        campaignGuid: z.string().min(1),
        properties: z.record(z.string(), z.any()),
      },
    },
    async ({ campaignGuid, properties }) => {
      requireWrite();
      assertId(campaignGuid, "campaign ID");
      return output(
        await hubspotRequest(`/marketing/v3/campaigns/${encodeURIComponent(campaignGuid)}`, {
          method: "PATCH",
          body: { properties },
        })
      );
    }
  );

  server.registerTool(
    "manage_campaign_asset",
    {
      description:
        "Associate an asset with a campaign (add) or remove it (remove). assetType examples: MARKETING_EMAIL, LANDING_PAGE, FORM, OBJECT_LIST, CTA, SOCIAL_BROADCAST. Use MARKETING_EMAIL with the email ID to attach each launch email.",
      inputSchema: {
        campaignGuid: z.string().min(1),
        action: z.enum(["add", "remove"]),
        assetType: z.string().min(1),
        assetId: z.string().min(1),
      },
    },
    async ({ campaignGuid, action, assetType, assetId }) => {
      requireWrite();
      [campaignGuid, assetType, assetId].forEach((v) => assertId(v, "campaign asset parameter"));
      const path = `/marketing/v3/campaigns/${encodeURIComponent(campaignGuid)}/assets/${encodeURIComponent(assetType)}/${encodeURIComponent(assetId)}`;
      return output(await hubspotRequest(path, { method: action === "add" ? "PUT" : "DELETE" }));
    }
  );

  // ================================================================ EMAIL, FILES, CRM WRITE TOOLS

  // Coded email templates live in the Design Manager and are written with the CMS Source Code API.
  server.registerTool(
    "upload_design_manager_file",
    {
      description:
        "Create or overwrite a Design Manager file (coded email template, module, CSS) via the CMS Source Code API. For an email template, the HTML must start with a HubL annotation comment containing templateType: email. Use environment 'published' so the template can be selected when creating emails.",
      inputSchema: {
        filePath: z.string().min(1).describe("e.g. custom/emails/JSG-Distributor-Quote-Follow-Up.html"),
        content: z.string().min(1).describe("Full file contents."),
        environment: z.enum(["draft", "published"]).optional().describe("Default: published"),
      },
    },
    async ({ filePath, content, environment }) => {
      requireWrite();
      const env = environment || "published";
      const fileName = filePath.split("/").pop();
      const form = new FormData();
      form.append("file", new Blob([content], { type: "text/html" }), fileName);
      return output(
        await hubspotMultipart(`/cms/v3/source-code/${env}/content/${encodeCmsPath(filePath)}`, form, "PUT")
      );
    }
  );

  server.registerTool(
    "create_marketing_email",
    {
      description:
        "Create a DRAFT marketing email. Pass templatePath to build it from a coded template (HubSpot may ignore it on create; if so, set content.templatePath with update_marketing_email). For an automated email, use emailType AUTOMATED_EMAIL (the server also sets subcategory 'automated' and state 'AUTOMATED_DRAFT', which HubSpot requires). Sender, subscription and other settings can be added later in HubSpot.",
      inputSchema: {
        name: z.string().min(1).describe("Internal email name."),
        subject: z.string().optional(),
        templatePath: z.string().optional().describe("Design Manager path, e.g. custom/emails/JSG-Distributor-Quote-Follow-Up.html"),
        fromName: z.string().optional(),
        replyTo: z.string().optional(),
        subscriptionId: z.string().optional(),
        businessUnitId: z.string().optional().describe("Brand / business unit ID, e.g. '0'."),
        emailType: z.enum(["BATCH_EMAIL", "AUTOMATED_EMAIL"]).optional(),
        extra: z.record(z.string(), z.any()).optional().describe("Any other v3 email fields, merged into the request body."),
      },
    },
    async ({ name, subject, templatePath, fromName, replyTo, subscriptionId, businessUnitId, emailType, extra }) => {
      requireWrite();
      const automated = emailType === "AUTOMATED_EMAIL" ? { subcategory: "automated", state: "AUTOMATED_DRAFT" } : {};
      const body = {
        name,
        ...(subject ? { subject } : {}),
        ...(templatePath ? { templatePath, content: { templatePath } } : {}),
        ...(emailType ? { type: emailType } : {}),
        ...automated,
        ...(businessUnitId !== undefined ? { businessUnitId } : {}),
        ...(fromName || replyTo ? { from: { ...(fromName ? { fromName } : {}), ...(replyTo ? { replyTo } : {}) } } : {}),
        ...(subscriptionId ? { subscriptionDetails: { subscriptionId } } : {}),
        ...(extra || {}),
      };
      return output(await hubspotRequest("/marketing/v3/emails", { method: "POST", body }));
    }
  );

  server.registerTool(
    "update_marketing_email",
    {
      description:
        "Update a draft marketing email (PATCH). Only the fields you pass are changed. Note: an email's type/subcategory cannot be changed after creation.",
      inputSchema: {
        emailId: z.string().min(1),
        changes: z.record(z.string(), z.any()).describe("v3 email fields to change, e.g. { subject, from, subscriptionDetails, content: { templatePath } }"),
      },
    },
    async ({ emailId, changes }) => {
      requireWrite();
      assertId(emailId, "email ID");
      return output(await hubspotRequest(`/marketing/v3/emails/${encodeURIComponent(emailId)}`, { method: "PATCH", body: changes }));
    }
  );

  server.registerTool(
    "clone_marketing_email",
    {
      description: "Copy an existing marketing email into a new draft (useful for building a series from one approved email).",
      inputSchema: {
        emailId: z.string().min(1).describe("ID of the email to copy."),
        cloneName: z.string().min(1).describe("Internal name for the copy."),
      },
    },
    async ({ emailId, cloneName }) => {
      requireWrite();
      assertId(emailId, "email ID");
      return output(
        await hubspotRequest("/marketing/v3/emails/clone", { method: "POST", body: { id: emailId, cloneName } })
      );
    }
  );

  server.registerTool(
    "set_email_recipients",
    {
      description:
        "Set which lists a draft marketing email sends to (include) and which it must not send to (exclude). Replaces the email's current list recipients. Uses list IDs from search_lists / get_list.",
      inputSchema: {
        emailId: z.string().min(1),
        includeListIds: z.array(z.string()).min(1).describe("'Send to' lists, e.g. ['1610']."),
        excludeListIds: z.array(z.string()).optional().describe("'Don't send to' lists, e.g. ['1611', '232']."),
      },
    },
    async ({ emailId, includeListIds, excludeListIds }) => {
      requireWrite();
      assertId(emailId, "email ID");
      [...includeListIds, ...(excludeListIds || [])].forEach((l) => assertId(l, "list ID"));
      return output(
        await hubspotRequest(`/marketing/v3/emails/${encodeURIComponent(emailId)}`, {
          method: "PATCH",
          body: { to: { contactIlsLists: { include: includeListIds, exclude: excludeListIds || [] } } },
        })
      );
    }
  );

  server.registerTool(
    "get_email_statistics",
    {
      description:
        "Read-only. Aggregated performance (sends, deliveries, opens, clicks, bounces, unsubscribes) for one or more marketing emails over a time range.",
      inputSchema: {
        emailIds: z.array(z.string()).min(1).max(100),
        startTimestamp: z.string().describe("ISO date-time, e.g. 2026-11-17T00:00:00Z"),
        endTimestamp: z.string().describe("ISO date-time, e.g. 2027-01-31T23:59:59Z"),
      },
    },
    async ({ emailIds, startTimestamp, endTimestamp }) => {
      emailIds.forEach((e) => assertId(e, "email ID"));
      return output(
        await hubspotRequest("/marketing/v3/emails/statistics/list", {
          query: { emailIds, startTimestamp, endTimestamp },
        })
      );
    }
  );

  server.registerTool(
    "upload_file",
    {
      description:
        "Upload an image or file to HubSpot File Manager and get back a public URL (for email images). Provide base64 content, or a public sourceUrl to import from.",
      inputSchema: {
        fileName: z.string().min(1).describe("e.g. justrite-logo.png"),
        folderPath: z.string().optional().describe("Default: /email-assets"),
        base64: z.string().optional(),
        mimeType: z.string().optional().describe("e.g. image/png"),
        sourceUrl: z.string().url().optional(),
      },
    },
    async ({ fileName, folderPath, base64, mimeType, sourceUrl }) => {
      requireWrite();
      const folder = folderPath || "/email-assets";
      if (sourceUrl) {
        return output(
          await hubspotRequest("/files/v3/files/import-from-url/async", {
            method: "POST",
            body: { url: sourceUrl, name: fileName, folderPath: folder, access: "PUBLIC_NOT_INDEXABLE", overwrite: true },
          })
        );
      }
      if (!base64) throw new Error("Provide base64 or sourceUrl.");
      const form = new FormData();
      form.append("file", new Blob([Buffer.from(base64, "base64")], { type: mimeType || "application/octet-stream" }), fileName);
      form.append("folderPath", folder);
      form.append("options", JSON.stringify({ access: "PUBLIC_NOT_INDEXABLE", overwrite: true }));
      return output(await hubspotMultipart("/files/v3/files", form));
    }
  );

  server.registerTool(
    "create_crm_record",
    {
      description:
        "Create a CRM record (contact, company, deal, ticket, task, note, or custom object) with optional associations. " +
        "Task for a contact: objectType 'tasks', properties { hs_task_subject, hs_task_body, hs_timestamp: '<ISO due date>', hs_task_status: 'NOT_STARTED', hs_task_priority: 'LOW' | 'MEDIUM' | 'HIGH', hubspot_owner_id (optional) }, " +
        "associations [{ to: { id: '<contactId>' }, types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: 204 }] }].",
      inputSchema: {
        objectType: z.string().min(1),
        properties: z.record(z.string(), z.string()),
        associations: z.array(z.any()).optional().describe("HubSpot v3 associations array, passed through as-is."),
      },
    },
    async ({ objectType, properties, associations }) => {
      requireWrite();
      assertId(objectType, "object type");
      return output(
        await hubspotRequest(`/crm/v3/objects/${encodeURIComponent(objectType)}`, {
          method: "POST",
          body: { properties, ...(associations?.length ? { associations } : {}) },
        })
      );
    }
  );

  server.registerTool(
    "update_crm_record",
    {
      description: "Update properties on an existing CRM record.",
      inputSchema: {
        objectType: z.string().min(1),
        recordId: z.string().min(1),
        properties: z.record(z.string(), z.string()),
      },
    },
    async ({ objectType, recordId, properties }) => {
      requireWrite();
      assertId(objectType, "object type");
      assertId(recordId, "record ID");
      return output(
        await hubspotRequest(`/crm/v3/objects/${encodeURIComponent(objectType)}/${encodeURIComponent(recordId)}`, {
          method: "PATCH",
          body: { properties },
        })
      );
    }
  );

  // HubSpot has no API to CREATE sequences; it can only enroll contacts in existing ones.
  server.registerTool(
    "enroll_in_sequence",
    {
      description:
        "Enroll a contact in an EXISTING sequence (sequences cannot be created by API). userId is the HubSpot user the sequence sends as. This SENDS email, so it requires confirm: true; only use after the user has explicitly confirmed.",
      inputSchema: {
        sequenceId: z.string().min(1),
        contactId: z.string().min(1),
        senderEmail: z.string().email(),
        userId: z.string().min(1),
        confirm: z.literal(true),
      },
    },
    async ({ sequenceId, contactId, senderEmail, userId, confirm }) => {
      requireWrite();
      if (confirm !== true) throw new Error("Enrolling in a sequence sends email. Pass confirm: true after the user confirms.");
      return output(
        await hubspotRequest("/automation/v4/sequences/enrollments", {
          method: "POST",
          query: { userId },
          body: { sequenceId, contactId, senderEmail },
        })
      );
    }
  );
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok", server: "hubspot-mcp-server", writeEnabled: WRITE_ENABLED });
});

app.post("/mcp", requireAuth, async (req, res) => {
  const server = new McpServer({ name: "personal-hubspot-mcp", version: "2.3.0" });
  registerTools(server);

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });

  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error.message);
    if (!res.headersSent) res.status(500).json({ error: "MCP request failed." });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`HubSpot MCP server listening on port ${PORT} (writes ${WRITE_ENABLED ? "enabled" : "disabled"})`);
});
