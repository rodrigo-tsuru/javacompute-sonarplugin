package br.com.tsuru.sonar.iib.jcn;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.sonar.java.JavaAstScanner;
import org.sonar.java.model.VisitorsBridge;
import org.sonar.squidbridge.api.SourceFile;
import org.sonar.squidbridge.checks.CheckMessagesVerifierRule;

import com.google.common.collect.ImmutableList;

public class AvoidDeprecatedParsersTest {

	  /** JAR dependencies for classpath execution */
	  private static final List<File> CLASSPATH_JAR;

	  static {
	    // Jar ClassPath construction. Don't use 'ClassLoader.getSystemClassLoader()', because with Maven+Surefire/Jacoco execution, only
	    // surefirebooter.jar & jacoco.agent-version-runtime.jar are on classpath => 'old schoold way'
	    CLASSPATH_JAR = new ArrayList();
	    CLASSPATH_JAR.add(new File("C:\\Users\\prica\\IBM\\SDPShared\\plugins\\com.ibm.etools.mft.jcn_9.0.200.v20140515-1210\\javacompute.jar"));
	    CLASSPATH_JAR.add(new File("C:\\Users\\prica\\IBM\\SDPShared\\plugins\\com.ibm.etools.mft.jcn_9.0.200.v20140515-1210\\jplugin2.jar"));
//	    for (String jar : System.getProperty("java.class.path").split(File.pathSeparator)) {
//	      if (jar.endsWith(".jar")) {
//	        CLASSPATH_JAR.add(new File(jar));
//	      }
//	    }
	  }
  @Rule
  public CheckMessagesVerifierRule checkMessagesVerifier = new CheckMessagesVerifierRule();

  @Test
  public void detected() {

    // Parse a known file and use an instance of the check under test to raise the issue.
    AvoidDeprecatedParsersCheck check = new AvoidDeprecatedParsersCheck();

    SourceFile file = JavaAstScanner
      .scanSingleFile(new File("src/test/files/AvoidDeprecatedParsersCheck.java"), new VisitorsBridge(check,CLASSPATH_JAR));
    	

    // Check the message raised by the check
    checkMessagesVerifier.verify(file.getCheckMessages())
      .next().atLine(28).withMessage("Should not use a deprecated parser!")
      .next().atLine(29);
  }
}
