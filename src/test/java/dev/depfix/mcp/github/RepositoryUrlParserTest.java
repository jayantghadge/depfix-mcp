package dev.depfix.mcp.github;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class RepositoryUrlParserTest {

  @Test
  void validSimpleUrl() {
    var p = RepositoryUrlParser.parse("https://github.com/spring-projects/spring-ai");
    assertEquals("spring-projects", p.owner());
    assertEquals("spring-ai", p.repo());
  }

  @Test
  void trailingSlashAndGitSuffix() {
    var p = RepositoryUrlParser.parse("https://github.com/OWNER/REPO.git/");
    assertEquals("OWNER", p.owner());
    assertEquals("REPO", p.repo());
  }

  @Test
  void treeUrlAcceptedWithBranchExtract() {
    var p = RepositoryUrlParser.parse("https://github.com/OWNER/REPO/tree/develop");
    assertEquals("OWNER", p.owner());
    assertEquals("develop", RepositoryUrlParser.extractBranchFromUrl("https://github.com/OWNER/REPO/tree/develop"));
  }

  @Test
  void rejectsNonGithubHost() {
    assertThrows(IllegalArgumentException.class,
        () -> RepositoryUrlParser.parse("https://gitlab.com/a/b"));
  }

  @Test
  void rejectsHttpAndMalformed() {
    assertThrows(IllegalArgumentException.class,
        () -> RepositoryUrlParser.parse("http://github.com/a/b"));
    assertThrows(IllegalArgumentException.class,
        () -> RepositoryUrlParser.parse("https://github.com/onlyowner"));
    assertThrows(IllegalArgumentException.class,
        () -> RepositoryUrlParser.parse("not a url"));
    assertThrows(IllegalArgumentException.class, () -> RepositoryUrlParser.parse("  "));
  }

  @Test
  void rejectsDeepUnsupportedPaths() {
    assertThrows(IllegalArgumentException.class,
        () -> RepositoryUrlParser.parse("https://github.com/a/b/issues/1"));
  }
}
