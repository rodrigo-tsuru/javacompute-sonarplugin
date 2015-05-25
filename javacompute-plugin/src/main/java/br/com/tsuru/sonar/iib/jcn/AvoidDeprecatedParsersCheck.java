package br.com.tsuru.sonar.iib.jcn;

import java.util.List;

import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.java.checks.methods.AbstractMethodDetection;
import org.sonar.java.checks.methods.MethodInvocationMatcher;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.LiteralTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.squidbridge.annotations.ActivatedByDefault;
import org.sonar.squidbridge.annotations.SqaleConstantRemediation;
import org.sonar.squidbridge.annotations.SqaleSubCharacteristic;

import com.google.common.collect.ImmutableList;

@Rule(
		  key = "JCN0004",
		  name = "Avoid using deprecated parsers",
		  tags = {"deprecated", "performance"},
		  priority = Priority.MINOR)
		@ActivatedByDefault
		@SqaleSubCharacteristic(RulesDefinition.SubCharacteristics.CPU_EFFICIENCY)
		@SqaleConstantRemediation("5min")
public class AvoidDeprecatedParsersCheck extends AbstractMethodDetection {

	 private static final List<String> DEPRECATED_PARSERS = ImmutableList.of("XMLNS","MRM");
	 
	 @Override
	  protected List<MethodInvocationMatcher> getMethodInvocationMatchers() {
	    return ImmutableList.of(MethodInvocationMatcher.create().typeDefinition("com.ibm.broker.plugin.MbElement").name("createElementAsLastChild").withNoParameterConstraint(),
	    		MethodInvocationMatcher.create().typeDefinition("com.ibm.broker.plugin.MbElement").name("createElementAsFirstChild").withNoParameterConstraint());
	  }

	  @Override
	  protected void onMethodFound(MethodInvocationTree mit) {
		  if(mit.arguments().size() == 1) {	  
			  ExpressionTree arg = mit.arguments().get(0);
			  if(arg.is(Tree.Kind.STRING_LITERAL)) {
					String argStr = ((LiteralTree) arg).value();
					if(DEPRECATED_PARSERS.contains(argStr)) {
						addIssue(mit, "Should not use a deprecated parser!");
					}
			  } else if(arg.is(Tree.Kind.MEMBER_SELECT)) {
				  MemberSelectExpressionTree mset = (MemberSelectExpressionTree) arg;
				  if(mset.expression().toString().equals("MbXMLNS") && mset.identifier().name().equals("ROOT_ELEMENT_NAME")) {
					  addIssue(mset, "Should not use a deprecated parser!");
				  }
				  if(mset.expression().toString().equals("MbMRM") && mset.identifier().name().equals("ROOT_ELEMENT_NAME")) {
					  addIssue(mset, "Should not use a deprecated parser!");
				  }
			  }
			  
		  }
	  }

}
