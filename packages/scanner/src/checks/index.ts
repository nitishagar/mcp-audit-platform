import { descriptionPoisoningCheck, paramCountCheck } from "./arg-validation.js";
import { inventoryCheck } from "./inventory.js";
import { auditLogCheck } from "./logging.js";
import { envSecretsCheck, valuePatternCheck } from "./secrets.js";
import { destructiveToolsCheck, toolCountCheck } from "./tool-privilege.js";
import { localhostBindingCheck, originValidationCheck, remoteAuthCheck } from "./transport-auth.js";
import type { Check } from "./types.js";

/** Full registry: every checkId the runner executes. */
export const CHECKS: Check[] = [
  inventoryCheck,
  remoteAuthCheck,
  localhostBindingCheck,
  originValidationCheck,
  destructiveToolsCheck,
  toolCountCheck,
  paramCountCheck,
  descriptionPoisoningCheck,
  envSecretsCheck,
  valuePatternCheck,
  auditLogCheck,
];

export const CHECK_IDS = CHECKS.map((c) => c.id);
