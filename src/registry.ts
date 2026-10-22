/** The parts of a registry "packument" (package document) that rules use. */
export interface Packument {
  /** Publish time per version (ISO 8601). */
  time: Record<string, string>;
  versions: Record<string, { deprecated?: string }>;
}

/** Fetches package metadata; null when the package does not exist. */
export interface Registry {
  packument(name: string): Promise<Packument | null>;
}
