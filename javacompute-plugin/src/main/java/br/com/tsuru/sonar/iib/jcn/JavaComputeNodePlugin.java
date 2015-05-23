package br.com.tsuru.sonar.iib.jcn;

import org.sonar.api.SonarPlugin;

import java.util.Arrays;
import java.util.List;

/**
 * Entry point of plugin
 */
public class JavaComputeNodePlugin extends SonarPlugin {

  @Override
  public List getExtensions() {
    return Arrays.asList(
      // server extensions -> objects are instantiated during server startup
      JavaComputeNodeRulesDefinition.class,

      // batch extensions -> objects are instantiated during code analysis
      JavaComputeNodeFileCheckRegistrar.class);
  }

}
