package dev.depfix.mcp.config;

import dev.depfix.mcp.tools.DepFixTools;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class McpToolConfiguration {

  @Bean
  public ToolCallbackProvider depFixToolCallbacks(DepFixTools tools) {
    return MethodToolCallbackProvider.builder().toolObjects(tools).build();
  }
}
