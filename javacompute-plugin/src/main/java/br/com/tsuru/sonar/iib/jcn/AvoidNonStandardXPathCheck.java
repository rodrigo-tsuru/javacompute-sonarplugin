package br.com.tsuru.sonar.iib.jcn;

import java.util.List;

import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.java.checks.SubscriptionBaseVisitor;
import org.sonar.java.checks.methods.MethodInvocationMatcher;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.LiteralTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.squidbridge.annotations.ActivatedByDefault;
import org.sonar.squidbridge.annotations.SqaleConstantRemediation;
import org.sonar.squidbridge.annotations.SqaleSubCharacteristic;

import com.google.common.collect.ImmutableList;

@Rule(
		  key = "JCN0003",
		  name = "Avoid using non-standard XPath",
		  tags = {"confusing", "portability"},
		  priority = Priority.MINOR)
		@ActivatedByDefault
		@SqaleSubCharacteristic(RulesDefinition.SubCharacteristics.UNDERSTANDABILITY)
		@SqaleConstantRemediation("30min")

public class AvoidNonStandardXPathCheck extends SubscriptionBaseVisitor {

	  private List<MethodInvocationMatcher> matchers = ImmutableList.of(MethodInvocationMatcher.create().typeDefinition("com.ibm.broker.plugin.MbMessage").name("evaluateXPath").withNoParameterConstraint(),
	    		MethodInvocationMatcher.create().typeDefinition("com.ibm.broker.plugin.MbElement").name("evaluateXPath").withNoParameterConstraint());

	  @Override
	  public List<Tree.Kind> nodesToVisit() {
	    return ImmutableList.of(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS);
	  }

	  @Override
	  public void visitNode(Tree tree) {
	    if (hasSemantic()) {
	    	if (tree.is(Tree.Kind.METHOD_INVOCATION)) {
			      MethodInvocationTree mit = (MethodInvocationTree) tree;
			      for (MethodInvocationMatcher invocationMatcher : this.matchers) {
			    	  if (invocationMatcher.matches(mit)) {
					        onMethodFound(mit);
					      }
				  }
			      
			    } else if (tree.is(Tree.Kind.NEW_CLASS)) {
			        onConstructorFound((NewClassTree)tree);
			    }
	      
	    }
	  }
	  
	  protected void onMethodFound(MethodInvocationTree mit) {
		for (ExpressionTree arg : mit.arguments()) {
			if(arg.is(Tree.Kind.STRING_LITERAL)) {
				String argStr = ((LiteralTree) arg).value();
				if(containsNonStandardXpath(argStr)) {
					addIssue(mit, "Do not use non-standard XPath!");
				}
			}
		} 
	  }
	  
	  protected void onConstructorFound(NewClassTree nct) {
		  if(nct.symbolType().fullyQualifiedName().equals("com.ibm.broker.plugin.MbXPath")) {
			for (ExpressionTree arg : nct.arguments()) {
				if(arg.is(Tree.Kind.STRING_LITERAL)) {
					String argStr = ((LiteralTree) arg).value();
					if(containsNonStandardXpath(argStr)) {
						addIssue(nct, "Do not use non-standard XPath!");
					}
				}
			} 
		  }
	  }

	private boolean containsNonStandardXpath(String argStr) {
		return argStr.contains("?") || argStr.contains("set-value");
	}

}
