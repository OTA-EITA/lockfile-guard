export type Severity = "high" | "medium" | "low";

export const severityRank: Record<Severity, number> = { high: 3, medium: 2, low: 1 };

export interface Finding {
  ruleId: string;
  severity: Severity;
  /** name@version */
  package: string;
  file: string;
  line: number;
  message: string;
  help?: string;
}

export interface Rule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  /** Rules that need registry metadata are skipped with --offline. */
  online: boolean;
}
