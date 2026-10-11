package dev.depfix.mcp.session;

import dev.depfix.mcp.github.RepositoryRef;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Component;

/** Holds the last repository selected via configure_repository (convenience, not permanent). */
@Component
public class RepositorySession {

  private final AtomicReference<RepositoryRef> current = new AtomicReference<>();

  public void set(RepositoryRef ref) {
    current.set(ref);
  }

  public RepositoryRef get() {
    return current.get();
  }
}
