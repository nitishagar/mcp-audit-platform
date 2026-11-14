import { descriptionPoisoningCheck, inputSchemaCheck, paramCountCheck } from "./arg-validation.js";
import { inventoryCheck } from "./inventory.js";
import { shadowDriftCheck } from "./shadow.js";
import { supplyChainCheck } from "./supply-chain.js";
import { auditLogCheck } from "./logging.js";
import { envSecretsCheck, valuePatternCheck } from "./secrets.js";
import {
  containerPrivilegeCheck,
  destructiveToolsCheck,
  filesystemBreadthCheck,
  toolCountCheck,
} from "./tool-privilege.js";
import {
  localhostBindingCheck,
  originValidationCheck,
  remoteAuthCheck,
  tlsCheck,
} from "./transport-auth.js";
import type { Check } from "./types.js";

/** Full registry: every checkId the runner executes. */
export const CHECKS: Check[] = [
  inventoryCheck,
  shadowDriftCheck,
  supplyChainCheck,
  remoteAuthCheck,
  localhostBindingCheck,
  originValidationCheck,
  tlsCheck,
  destructiveToolsCheck,
  toolCountCheck,
  filesystemBreadthCheck,
  containerPrivilegeCheck,
  paramCountCheck,
  descriptionPoisoningCheck,
  inputSchemaCheck,
  envSecretsCheck,
  valuePatternCheck,
  auditLogCheck,
];

export const CHECK_IDS = CHECKS.map((c) => c.id);
