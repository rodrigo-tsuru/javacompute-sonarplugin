package br.com.tsuru.sonar.iib.jcn;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;

import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.java.checks.SubscriptionBaseVisitor;
import org.sonar.java.checks.methods.MethodInvocationMatcher;
import org.sonar.java.checks.methods.MethodInvocationMatcherCollection;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.AssignmentExpressionTree;
import org.sonar.plugins.java.api.tree.BaseTreeVisitor;
import org.sonar.plugins.java.api.tree.BlockTree;
import org.sonar.plugins.java.api.tree.CaseGroupTree;
import org.sonar.plugins.java.api.tree.CaseLabelTree;
import org.sonar.plugins.java.api.tree.CatchTree;
import org.sonar.plugins.java.api.tree.ClassTree;
import org.sonar.plugins.java.api.tree.DoWhileStatementTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.ForEachStatement;
import org.sonar.plugins.java.api.tree.ForStatementTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.IfStatementTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.ReturnStatementTree;
import org.sonar.plugins.java.api.tree.StatementTree;
import org.sonar.plugins.java.api.tree.SwitchStatementTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.TryStatementTree;
import org.sonar.plugins.java.api.tree.TypeCastTree;
import org.sonar.plugins.java.api.tree.VariableTree;
import org.sonar.plugins.java.api.tree.WhileStatementTree;
import org.sonar.squidbridge.annotations.ActivatedByDefault;
import org.sonar.squidbridge.annotations.SqaleConstantRemediation;
import org.sonar.squidbridge.annotations.SqaleSubCharacteristic;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

@Rule(
  key = "JCN0005",
  name = "MbMessages should be cleared",
  tags = {"bug", "cert", "cwe", "denial-of-service", "leak", "security"},
  priority = Priority.BLOCKER)
@ActivatedByDefault
@SqaleSubCharacteristic(RulesDefinition.SubCharacteristics.LOGIC_RELIABILITY)
@SqaleConstantRemediation("5min")
public class ClearMbMessageCheck extends SubscriptionBaseVisitor {

  private enum State {

    // * | C | O | I | N |
    // --+---+---+---+---|
    // C | C | O | I | C | <- CLEARED
    // --+---+---+---+---|
    // O | O | O | I | O | <- OPEN
    // --+---+---+---+---|
    // I | I | I | I | I | <- IGNORED
    // --+---+---+---+---|
    // N | C | O | I | N | <- NULL
    // ------------------+

    NULL {
      @Override
      public State merge(State s) {
        return s;
      }
    },
    CLEARED {
      @Override
      public State merge(State s) {
        if (s == NULL) {
          return this;
        }
        return s;
      }
    },
    OPEN {
      @Override
      public State merge(State s) {
        if (s == IGNORED) {
          return s;
        }
        return this;
      }
    },
    IGNORED {
      @Override
      public State merge(State s) {
        return this;
      }
    };

    public abstract State merge(State s);

    public boolean isIgnored() {
      return this.equals(IGNORED);
    }

    public boolean isOpen() {
      return this.equals(OPEN);
    }
  }

  private static final String CLEAR_METHOD_NAME = "clearMessage";
  private static final String MBMESSAGE = "com.ibm.broker.plugin.MbMessage";

  private static final MethodInvocationMatcherCollection CLOSE_INVOCATIONS = closeMethodInvocationMatcher();

  @Override
  public List<Tree.Kind> nodesToVisit() {
    return ImmutableList.of(Tree.Kind.METHOD);
  }

  @Override
  public void visitNode(Tree tree) {
    if (!hasSemantic()) {
      return;
    }

    MethodTree methodTree = (MethodTree) tree;
    BlockTree block = methodTree.block();
    if (block != null) {
    	System.out.println(block);
      ClearableVisitor visitor = new ClearableVisitor(methodTree.parameters(), this);
      block.accept(visitor);
      visitor.executionState.insertIssues();
    }
  }

  private static MethodInvocationMatcherCollection closeMethodInvocationMatcher() {
    return MethodInvocationMatcherCollection.create(
      MethodInvocationMatcher.create()
        .typeDefinition(MBMESSAGE)
        .name(CLEAR_METHOD_NAME)
        .withNoParameterConstraint()
        );
  }

  private static boolean isClearableOrAutoClearableSubtype(Type type) {
    return type.isSubtypeOf(MBMESSAGE);
  }


  private static class ClearableVisitor extends BaseTreeVisitor {

    private ExecutionState executionState;

    public ClearableVisitor(List<VariableTree> methodParameters, SubscriptionBaseVisitor check) {
      executionState = new ExecutionState(extractClearableSymbols(methodParameters), check);
    }

    @Override
    public void visitVariable(VariableTree tree) {
      ExpressionTree initializer = tree.initializer();

      // check first usage of Clearables in order to manage use of same symbol
      executionState.checkUsageOfClosables(initializer);

      Symbol symbol = tree.symbol();
      if (isClearableOrAutoClearableSubtype(symbol.type())) {
        executionState.addClearable(symbol, tree, initializer);
      }
    }

    @Override
    public void visitAssignmentExpression(AssignmentExpressionTree tree) {
      ExpressionTree variable = tree.variable();
      if (variable.is(Tree.Kind.IDENTIFIER, Tree.Kind.MEMBER_SELECT)) {
        ExpressionTree expression = tree.expression();

        // check first usage of Clearables in order to manage use of same symbol
        executionState.checkUsageOfClosables(expression);

        IdentifierTree identifier;
        if (variable.is(Tree.Kind.IDENTIFIER)) {
          identifier = (IdentifierTree) variable;
        } else {
          identifier = ((MemberSelectExpressionTree) variable).identifier();
        }
        Symbol symbol = identifier.symbol();
        if (isClearableOrAutoClearableSubtype(identifier.symbolType()) && symbol.owner().isMethodSymbol()) {
          executionState.addClearable(symbol, identifier, expression);
        }
      }
    }

    @Override
    public void visitNewClass(NewClassTree tree) {
      executionState.checkUsageOfClosables(tree.arguments());
    }

    @Override
    public void visitMethodInvocation(MethodInvocationTree tree) {
      if (CLOSE_INVOCATIONS.anyMatch(tree)) {
        ExpressionTree methodSelect = tree.methodSelect();
        if (methodSelect.is(Tree.Kind.MEMBER_SELECT)) {
          ExpressionTree expression = ((MemberSelectExpressionTree) methodSelect).expression();
          if (expression.is(Tree.Kind.IDENTIFIER)) {
            executionState.markAsCleared(((IdentifierTree) expression).symbol());
          }
        }
      } else {
        executionState.checkUsageOfClosables(tree.arguments());
      }
    }

    @Override
    public void visitClass(ClassTree tree) {
      // do nothing, inner methods will be visited later
    }

    @Override
    public void visitReturnStatement(ReturnStatementTree tree) {
      executionState.checkUsageOfClosables(tree.expression());
    }

    @Override
    public void visitTryStatement(TryStatementTree tree) {
      for (VariableTree resource : tree.resources()) {
        executionState.markAsIgnored(resource.symbol());
      }

      ExecutionState blockES = new ExecutionState(executionState);
      executionState = blockES;
      scan(tree.block());

      for (CatchTree catchTree : tree.catches()) {
        executionState = new ExecutionState(blockES.parent);
        scan(catchTree.block());
        blockES.merge(executionState);
      }

      if (tree.finallyBlock() != null) {
        executionState = new ExecutionState(blockES.parent);
        scan(tree.finallyBlock());
        executionState = blockES.parent.overrideBy(blockES.overrideBy(executionState));
      } else {
        executionState = blockES.parent.merge(blockES);
      }
    }

    @Override
    public void visitIfStatement(IfStatementTree tree) {
      scan(tree.condition());
      ExecutionState thenES = new ExecutionState(executionState);
      executionState = thenES;
      scan(tree.thenStatement());

      if (tree.elseStatement() == null) {
        executionState = thenES.parent.merge(thenES);
      } else {
        ExecutionState elseES = new ExecutionState(thenES.parent);
        executionState = elseES;
        scan(tree.elseStatement());
        executionState = thenES.parent.overrideBy(thenES.merge(elseES));
      }
    }

    @Override
    public void visitSwitchStatement(SwitchStatementTree tree) {
      scan(tree.expression());
      ExecutionState resultingES = new ExecutionState(executionState);
      executionState = new ExecutionState(executionState);
      for (CaseGroupTree caseGroupTree : tree.cases()) {
        for (StatementTree statement : caseGroupTree.body()) {
          if (isBreakOrReturnStatement(statement)) {
            resultingES = executionState.merge(resultingES);
            executionState = new ExecutionState(resultingES.parent);
          } else {
            scan(statement);
          }
        }
      }
      if (!lastStatementIsBreakOrReturn(tree)) {
        // merge the last execution state
        resultingES = executionState.merge(resultingES);
      }

      if (switchContainsDefaultLabel(tree)) {
        // the default block guarantees that we will cover all the paths
        executionState = resultingES.parent.overrideBy(resultingES);
      } else {
        executionState = resultingES.parent.merge(resultingES);
      }
    }

    private boolean isBreakOrReturnStatement(StatementTree statement) {
      return statement.is(Tree.Kind.BREAK_STATEMENT, Tree.Kind.RETURN_STATEMENT);
    }

    private boolean switchContainsDefaultLabel(SwitchStatementTree tree) {
      for (CaseGroupTree caseGroupTree : tree.cases()) {
        for (CaseLabelTree label : caseGroupTree.labels()) {
          if ("default".equals(label.caseOrDefaultKeyword().text())) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean lastStatementIsBreakOrReturn(SwitchStatementTree tree) {
      List<CaseGroupTree> cases = tree.cases();
      if (!cases.isEmpty()) {
        List<StatementTree> lastStatements = cases.get(cases.size() - 1).body();
        return !lastStatements.isEmpty() && isBreakOrReturnStatement(lastStatements.get(lastStatements.size() - 1));
      }
      return false;
    }

    @Override
    public void visitWhileStatement(WhileStatementTree tree) {
      scan(tree.condition());
      visitStatement(tree.statement());
    }

    @Override
    public void visitDoWhileStatement(DoWhileStatementTree tree) {
      visitStatement(tree.statement());
      scan(tree.condition());
    }

    @Override
    public void visitForStatement(ForStatementTree tree) {
      scan(tree.condition());
      scan(tree.initializer());
      scan(tree.update());
      visitStatement(tree.statement());
    }

    @Override
    public void visitForEachStatement(ForEachStatement tree) {
      scan(tree.variable());
      scan(tree.expression());
      visitStatement(tree.statement());
    }

    private void visitStatement(StatementTree tree) {
      executionState = new ExecutionState(executionState);
      scan(tree);
      executionState = executionState.restoreParent();
    }

    private Set<Symbol> extractClearableSymbols(List<VariableTree> variableTrees) {
      Set<Symbol> symbols = Sets.newHashSet();
      for (VariableTree variableTree : variableTrees) {
        Symbol symbol = variableTree.symbol();
        if (isClearableOrAutoClearableSubtype(symbol.type())) {
          symbols.add(symbol);
        }
      }
      return symbols;
    }
  }

  private static class ClearableOccurence {

    private static final ClearableOccurence IGNORED = new ClearableOccurence(null, State.IGNORED);
    @Nullable
    private Tree lastAssignment;
    private State state;

    public ClearableOccurence(@Nullable Tree lastAssignment, State state) {
      this.lastAssignment = lastAssignment;
      this.state = state;
    }
  }

  private static class ExecutionState {
    @Nullable
    private ExecutionState parent;
    private Map<Symbol, ClearableOccurence> ClearableOccurenceBySymbol = Maps.newHashMap();
    private IssuableSubscriptionVisitor check;

    ExecutionState(Set<Symbol> excludedClearables, IssuableSubscriptionVisitor check) {
      this.check = check;
      for (Symbol symbol : excludedClearables) {
        ClearableOccurenceBySymbol.put(symbol, ClearableOccurence.IGNORED);
      }
    }

    public ExecutionState(ExecutionState parent) {
      this.parent = parent;
      this.check = parent.check;
    }

    public ExecutionState merge(ExecutionState executionState) {
      for (Entry<Symbol, ClearableOccurence> entry : executionState.ClearableOccurenceBySymbol.entrySet()) {
        Symbol symbol = entry.getKey();
        ClearableOccurence currentOccurence = getClearableOccurence(symbol);
        ClearableOccurence occurenceToMerge = entry.getValue();
        if (currentOccurence != null) {
          currentOccurence.state = currentOccurence.state.merge(occurenceToMerge.state);
          ClearableOccurenceBySymbol.put(symbol, currentOccurence);
        } else if (occurenceToMerge.state.isOpen()) {
          insertIssue(occurenceToMerge.lastAssignment);
        }
      }
      return this;
    }

    public ExecutionState overrideBy(ExecutionState currentES) {
      for (Entry<Symbol, ClearableOccurence> entry : currentES.ClearableOccurenceBySymbol.entrySet()) {
        Symbol symbol = entry.getKey();
        ClearableOccurence occurence = entry.getValue();
        if (getClearableOccurence(symbol) != null) {
          markAs(symbol, occurence.state);
        } else {
          ClearableOccurenceBySymbol.put(symbol, occurence);
        }
      }
      return this;
    }

    public ExecutionState restoreParent() {
      if (parent != null) {
        insertIssues();
        return parent.merge(this);
      }
      return this;
    }

    private void insertIssues() {
      for (Tree tree : getUnclosedClosables()) {
        insertIssue(tree);
      }
    }

    private void insertIssue(Tree tree) {
      check.addIssue(tree, "Clear this MbMessage");
    }

    private void addClearable(Symbol symbol, Tree lastAssignmentTree, @Nullable ExpressionTree assignmentExpression) {
      ClearableOccurence newOccurence = new ClearableOccurence(lastAssignmentTree, getClearableStateFromExpression(symbol, assignmentExpression));
      ClearableOccurence knownOccurence = getClearableOccurence(symbol);
      if (knownOccurence != null) {
        ClearableOccurence currentOccurence = ClearableOccurenceBySymbol.get(symbol);
        if (currentOccurence != null && currentOccurence.state.isOpen()) {
          insertIssue(knownOccurence.lastAssignment);
        }
        if (!knownOccurence.state.isIgnored()) {
          ClearableOccurenceBySymbol.put(symbol, newOccurence);
        }
      } else {
        ClearableOccurenceBySymbol.put(symbol, newOccurence);
      }
    }

    private State getClearableStateFromExpression(Symbol symbol, @Nullable ExpressionTree expression) {
      if (shouldBeIgnored(symbol, expression)) {
        return State.IGNORED;
      } else if (isNull(expression)) {
        return State.NULL;
      } else if (expression.is(Tree.Kind.NEW_CLASS)) {
        if (usesIgnoredClearableAsArgument(((NewClassTree) expression).arguments())) {
          return State.IGNORED;
        }
        return State.OPEN;
      }
      // TODO SONARJAVA-1029 : Engine currently ignore Clearables which are retrieved from method calls. Handle them as OPEN.
      return State.IGNORED;
    }

    private static boolean isNull(ExpressionTree expression) {
      return expression == null || expression.is(Tree.Kind.NULL_LITERAL);
    }

    private static boolean shouldBeIgnored(Symbol symbol, @Nullable ExpressionTree expression) {
      return false;
    }

    private static boolean shouldBeIgnored(Symbol symbol) {
      return false;
    }

    private static boolean shouldBeIgnored(@Nullable ExpressionTree expression) {
      return false;
    }

    private boolean usesIgnoredClearableAsArgument(List<ExpressionTree> arguments) {
//      for (ExpressionTree argument : arguments) {
//        if (isNewClassWithIgnoredArguments(argument)) {
//          return true;
//        } else if (isMethodInvocationWithIgnoredArguments(argument)) {
//          return true;
//        } else if (useIgnoredClearable(argument) ) {
//          return true;
//        }
//      }
      return false;
    }

    private void checkUsageOfClosables(List<ExpressionTree> expressions) {
      for (ExpressionTree expression : expressions) {
        checkUsageOfClosables(expression);
      }
    }

    private void checkUsageOfClosables(@Nullable ExpressionTree expression) {
      if (expression != null) {
        if (expression.is(Tree.Kind.MEMBER_SELECT)) {
          checkUsageOfClosables(((MemberSelectExpressionTree) expression).identifier());
        } else if (expression.is(Tree.Kind.TYPE_CAST)) {
          checkUsageOfClosables(((TypeCastTree) expression).expression());
        } else if (expression.is(Tree.Kind.METHOD_INVOCATION)) {
          checkUsageOfClosables(((MethodInvocationTree) expression).arguments());
        } else if (expression.is(Tree.Kind.NEW_CLASS)) {
          checkUsageOfClosables(((NewClassTree) expression).arguments());
        }
      }
    }

    private void markAsIgnored(Symbol symbol) {
      markAs(symbol, State.IGNORED);
    }

    private void markAsCleared(Symbol symbol) {
      markAs(symbol, State.CLEARED);
    }

    private void markAs(Symbol symbol, State state) {
      if (ClearableOccurenceBySymbol.containsKey(symbol)) {
        ClearableOccurenceBySymbol.get(symbol).state = state;
      } else if (parent != null) {
        ClearableOccurence occurence = getClearableOccurence(symbol);
        if (occurence != null) {
          occurence.state = state;
          ClearableOccurenceBySymbol.put(symbol, occurence);
        }
      }
    }

    private Set<Tree> getUnclosedClosables() {
      Set<Tree> results = Sets.newHashSet();
      for (ClearableOccurence occurence : ClearableOccurenceBySymbol.values()) {
        if (occurence.state.isOpen()) {
          results.add(occurence.lastAssignment);
        }
      }
      return results;
    }

    @CheckForNull
    private ClearableOccurence getClearableOccurence(Symbol symbol) {
      ClearableOccurence occurence = ClearableOccurenceBySymbol.get(symbol);
      if (occurence != null) {
        return new ClearableOccurence(occurence.lastAssignment, occurence.state);
      } else if (parent != null) {
        return parent.getClearableOccurence(symbol);
      }
      return null;
    }
  }
}
