package dev.depfix.mcp.parser;

import dev.depfix.mcp.model.DependencyRecord;
import dev.depfix.mcp.model.DetectedFile;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * Parses Maven {@code pom.xml}: direct dependencies, scopes, versions with
 * {@code ${property}} resolution. Never executes project code; effective-POM
 * resolution beyond properties is out of scope and reported as a limitation.
 */
@Component
public class MavenPomParser implements DependencyAnalyzer {

  @Override
  public boolean supports(DetectedFile file) {
    return "maven".equals(file.ecosystem()) && file.path().endsWith("pom.xml");
  }

  @Override
  public ParseOutcome analyze(String path, String content) {
    List<DependencyRecord> deps = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    try {
      DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
      f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      f.setFeature("http://xml.org/sax/features/external-general-entities", false);
      f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      f.setExpandEntityReferences(false);
      var doc = f.newDocumentBuilder().parse(new InputSource(new StringReader(content)));
      doc.getDocumentElement().normalize();

      Map<String, String> props = new HashMap<>();
      NodeList propsNodes = doc.getElementsByTagName("properties");
      for (int i = 0; i < propsNodes.getLength(); i++) {
        var children = propsNodes.item(i).getChildNodes();
        for (int j = 0; j < children.getLength(); j++) {
          var c = children.item(j);
          if (c instanceof Element e) {
            props.put(e.getTagName(), e.getTextContent().trim());
          }
        }
      }

      NodeList allDeps = doc.getElementsByTagName("dependency");
      for (int i = 0; i < allDeps.getLength(); i++) {
        var d = (Element) allDeps.item(i);
        if (isUnderDependencyManagement(d)) continue;
        String groupId = text(d, "groupId");
        String artifactId = text(d, "artifactId");
        String rawVersion = text(d, "version");
        String scope = text(d, "scope");
        String type = text(d, "type");
        if (artifactId.isBlank()) continue;
        String name = groupId.isBlank() ? artifactId : groupId + ":" + artifactId;
        String declared = rawVersion.isBlank() ? null : rawVersion;
        String status = null;
        if (declared != null && declared.startsWith("${") && declared.endsWith("}")) {
          String key = declared.substring(2, declared.length() - 1);
          String resolved = props.get(key);
          if (resolved != null && !resolved.isBlank()) {
            declared = resolved;
            status = "version property ${" + key + "} resolved from <properties>";
          } else {
            status = "unresolved version property " + declared;
          }
        }
        if (declared == null) {
          status = status == null
              ? "no <version>: managed externally or inherited (not resolved)"
              : status;
          warnings.add(path + ": dependency " + name + " has no version; managed/inherited versions are not resolved in Phase 1.");
        }
        if (!type.isBlank() && !"jar".equals(type)) {
          String t = status == null ? "" : status + "; ";
          status = t + "packaging type: " + type;
        }
        deps.add(new DependencyRecord("maven", name, declared, null,
            scope.isBlank() ? "compile" : scope, "direct", path, "manifest", status));
      }
      if (allDeps.getLength() == 0) {
        warnings.add(path + ": no <dependency> entries found.");
      }
    } catch (Exception e) {
      warnings.add(path + ": failed to parse pom.xml (" + e.getMessage() + "). File reported as detected but not analyzed.");
      return ParseOutcome.of(List.of(), warnings);
    }
    return ParseOutcome.of(deps, warnings);
  }

  private static boolean isUnderDependencyManagement(Element d) {
    var p = d.getParentNode();
    while (p != null) {
      if (p instanceof Element e && "dependencyManagement".equals(e.getTagName())) return true;
      p = p.getParentNode();
    }
    return false;
  }

  private static String text(Element parent, String tag) {
    NodeList nl = parent.getElementsByTagName(tag);
    // Only direct children to avoid picking nested values.
    for (int i = 0; i < nl.getLength(); i++) {
      if (nl.item(i).getParentNode() == parent) {
        return nl.item(i).getTextContent().trim();
      }
    }
    return "";
  }
}
