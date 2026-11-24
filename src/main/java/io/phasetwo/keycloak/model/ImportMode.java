package io.phasetwo.keycloak.model;

import java.util.Locale;

/**
 * How {@code POST authentication-flow/import} treats flows that already exist in the realm.
 *
 * <ul>
 *   <li>{@link #VERSIONED} — every import creates a new, independently bindable set of flows whose
 *       aliases are prefixed with a hash of the payload. Nothing that exists is modified, so
 *       previous versions stay in the realm for rollback. Re-posting an identical payload is
 *       rejected with {@code 409} unless {@code force=true}.
 *   <li>{@link #REPLACE} — flows keep the plain aliases from the payload. A flow that already
 *       exists is overwritten in place (same id, new executions), a missing one is created, and
 *       re-posting an identical payload is a no-op. This is the mode to use when another
 *       config-as-code tool (Terraform, keycloak-config-cli, ...) also expects to find flows under
 *       their configured names.
 * </ul>
 */
public enum ImportMode {
  VERSIONED,
  REPLACE;

  /**
   * Parses a mode name case-insensitively. A {@code null} or blank value yields {@code
   * defaultMode}; an unknown value throws {@link IllegalArgumentException}.
   */
  public static ImportMode parse(String value, ImportMode defaultMode) {
    if (value == null || value.isBlank()) {
      return defaultMode;
    }
    try {
      return ImportMode.valueOf(value.trim().toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Unknown import mode '%s'. Expected one of: versioned, replace".formatted(value));
    }
  }
}
