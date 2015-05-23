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

import br.com.tsuru.sonar.iib.jcn.JavaComputeNodeFieldCheck;

import com.google.common.collect.ImmutableList;

public class AvoidCloseJDBCConnectionTest {

  @Rule
  public CheckMessagesVerifierRule checkMessagesVerifier = new CheckMessagesVerifierRule();

  @Test
  public void detected() {

    // Parse a known file and use an instance of the check under test to raise the issue.
    AvoidCloseJDBCConnectionCheck check = new AvoidCloseJDBCConnectionCheck();

    SourceFile file = JavaAstScanner
      .scanSingleFile(new File("src/test/files/AvoidCloseJDBCConnectionCheck.java"), new VisitorsBridge(check,ImmutableList.of(new File("target/test-classes"))));
    	

    // Check the message raised by the check
    checkMessagesVerifier.verify(file.getCheckMessages())
      .next().atLine(43).withMessage("Should not close a JDBC Connection provided by IIB!");
  }
}
