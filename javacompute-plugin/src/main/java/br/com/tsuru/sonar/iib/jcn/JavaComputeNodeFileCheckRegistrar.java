
package br.com.tsuru.sonar.iib.jcn;

import org.sonar.java.checks.SystemExitCalledCheck;
import org.sonar.java.checks.SystemOutOrErrUsageCheck;
import org.sonar.plugins.java.api.CheckRegistrar;
import org.sonar.plugins.java.api.JavaCheck;

import java.util.Arrays;

/**
 * Provide the "checks" (implementations of rules) classes that are gonna be executed during
 * source code analysis.
 *
 * This class is a batch extension by implementing the {@link org.sonar.plugins.java.api.CheckRegistrar} interface.
 */
public class JavaComputeNodeFileCheckRegistrar implements CheckRegistrar {

  /**
   * Register the classes that will be used to instantiate checks during analysis.
   */
  @Override
  public void register(RegistrarContext registrarContext) {
    //Call to registerClassesForRepository to associate the classes with the correct repository key
    registrarContext.registerClassesForRepository(JavaComputeNodeRulesDefinition.REPOSITORY_KEY, Arrays.asList(checkClasses()));
  }

  /**
   * Lists all the checks provided by the plugin
   */
  public static Class<? extends JavaCheck>[] checkClasses() {
    return new Class[] {JavaComputeNodeFieldCheck.class,AvoidCloseJDBCConnectionCheck.class,SystemExitCalledCheck.class,SystemOutOrErrUsageCheck.class};
  }
}
