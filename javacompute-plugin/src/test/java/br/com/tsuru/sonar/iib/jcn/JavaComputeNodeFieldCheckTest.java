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

public class JavaComputeNodeFieldCheckTest {

  @Rule
  public CheckMessagesVerifierRule checkMessagesVerifier = new CheckMessagesVerifierRule();

  @Test
  public void detected() {

    // Parse a known file and use an instance of the check under test to raise the issue.
    JavaComputeNodeFieldCheck check = new JavaComputeNodeFieldCheck();

    SourceFile file = JavaAstScanner
      .scanSingleFile(new File("src/test/files/JavaComputeNodeFieldCheck.java"), new VisitorsBridge(check,ImmutableList.of(new File("target/test-classes"))));
    	

    // Check the message raised by the check
    checkMessagesVerifier.verify(file.getCheckMessages())
      .next().atLine(11).withMessage("Remove this misleading mutable Java Compute Node fields or make it \"static\" and/or \"final\"");
  }
}
