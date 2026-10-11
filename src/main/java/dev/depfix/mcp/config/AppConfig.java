package dev.depfix.mcp.config;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

  @Bean
  public HttpClient gitHubHttpClient(
      @Value("${depfix.github.connect-timeout-ms:10000}") long connectTimeoutMs) {
    return HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(connectTimeoutMs))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }
}
