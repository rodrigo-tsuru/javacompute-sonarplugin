package br.com.tsuru.sonar.iib.jcn;

import java.util.List;

import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.java.checks.methods.AbstractMethodDetection;
import org.sonar.java.checks.methods.MethodInvocationMatcher;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.squidbridge.annotations.ActivatedByDefault;
import org.sonar.squidbridge.annotations.SqaleConstantRemediation;
import org.sonar.squidbridge.annotations.SqaleSubCharacteristic;

import com.google.common.collect.ImmutableList;

@Rule(
		  key = "JCN0002",
		  name = "Should never close JDBC Connection because IIB controls it",
		  tags = {"bug", "database", "jdbc"},
		  priority = Priority.CRITICAL)
		@ActivatedByDefault
		@SqaleSubCharacteristic(RulesDefinition.SubCharacteristics.ARCHITECTURE_RELIABILITY)
		@SqaleConstantRemediation("5min")
public class AvoidCloseJDBCConnectionCheck extends AbstractMethodDetection {

	 @Override
	  protected List<MethodInvocationMatcher> getMethodInvocationMatchers() {
	    return ImmutableList.of(MethodInvocationMatcher.create().typeDefinition("java.sql.Connection").name("close").withNoParameterConstraint());
	  }

	  @Override
	  protected void onMethodFound(MethodInvocationTree mit) {
	    addIssue(mit, "Should not close a JDBC Connection provided by IIB!");
	  }

}
