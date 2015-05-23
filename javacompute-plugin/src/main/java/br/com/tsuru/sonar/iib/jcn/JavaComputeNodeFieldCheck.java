package br.com.tsuru.sonar.iib.jcn;

import java.util.List;

import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.java.checks.SubscriptionBaseVisitor;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Modifier;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.Tree.Kind;
import org.sonar.plugins.java.api.tree.VariableTree;
import org.sonar.squidbridge.annotations.ActivatedByDefault;
import org.sonar.squidbridge.annotations.SqaleConstantRemediation;
import org.sonar.squidbridge.annotations.SqaleSubCharacteristic;

import com.google.common.collect.ImmutableList;

@Rule(
		  key = "JCN0001",
		  name = "Java Compute Nodes should never have mutable instance fields",
		  tags = {"bug", "cert", "multi-threading"},
		  priority = Priority.CRITICAL)
		@ActivatedByDefault
		@SqaleSubCharacteristic(RulesDefinition.SubCharacteristics.SYNCHRONIZATION_RELIABILITY)
		@SqaleConstantRemediation("30min")
public class JavaComputeNodeFieldCheck extends SubscriptionBaseVisitor {

	@Override
	public List<Kind> nodesToVisit() {
		
		return ImmutableList.of(Tree.Kind.VARIABLE);
	}

	 @Override
	  public void visitNode(Tree tree) {
	    VariableTree variable = (VariableTree) tree;
	    if (hasSemantic() && isOwnedByAJCN(variable) && !isStaticOrFinal(variable)) {
	      addIssue(tree, "Remove this misleading mutable Java Compute Node fields or make it \"static\" and/or \"final\"");
	    }
	  }

	 
	  private boolean isOwnedByAJCN(VariableTree variable) {
	    Symbol owner = variable.symbol().owner();
	    if (owner.isTypeSymbol()) {
	      return owner.type().isSubtypeOf("com.ibm.broker.javacompute.MbJavaComputeNode");
	    }
	    return false;
	  }

	  private boolean isStaticOrFinal(VariableTree variable) {
	    List<Modifier> modifiers = variable.modifiers().modifiers();
	    return modifiers.contains(Modifier.STATIC) || modifiers.contains(Modifier.FINAL);
	  }
}
