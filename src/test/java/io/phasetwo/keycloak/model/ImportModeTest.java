package io.phasetwo.keycloak.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ImportModeTest {

  @Test
  void nullOrBlank_yieldsDefault() {
    assertEquals(ImportMode.VERSIONED, ImportMode.parse(null, ImportMode.VERSIONED));
    assertEquals(ImportMode.REPLACE, ImportMode.parse("  ", ImportMode.REPLACE));
  }

  @Test
  void parse_isCaseInsensitive() {
    assertEquals(ImportMode.REPLACE, ImportMode.parse("replace", ImportMode.VERSIONED));
    assertEquals(ImportMode.REPLACE, ImportMode.parse("Replace", ImportMode.VERSIONED));
    assertEquals(ImportMode.VERSIONED, ImportMode.parse("VERSIONED", ImportMode.REPLACE));
  }

  @Test
  void unknownValue_throws() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> ImportMode.parse("bogus", ImportMode.VERSIONED));
    assertEquals(
        "Unknown import mode 'bogus'. Expected one of: versioned, replace", e.getMessage());
  }
}
