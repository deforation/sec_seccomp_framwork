###################################################################
# Seccomp Toolkit by Remo Schweizer as a part of the master thesis
#                  ____ _ _  ___  _ _ _ 
#                 |_  /| | || . || | | |
#                  / / |   ||   || | | |
#                 /___||_|_||_|_||__/_/ 
#                      
# The SecConfigBuilder is the main script which takes
# a systemcall configuration file (c-code) [sec_syscall_conf.c] 
# a rule file (inf-file) [sec_rules.ini] defining allowed actions on 
# systemcalls and a second (ini-file) [source_templates.ini] 
# defining code snippets (templates) to produce the following
# output:
#
# - sec_seccomp_rules.c:      
#   Seccomp rule set for the client and tracer part of the app
# - sec_seccomp_rules.h:
#   Corresponding header file
# - sec_syscall_emulator.c:
#   Generated source for the tracer to (modify, terminate,
#   allow or skip) systemcalls.
# - sec_syscall_emulator.h:
#   Corresponding header file
#
# Basic expressions which only contain primitive datatypes
# and non complex expressions (combination of && and || checks)
# are directly transformed into seccomp rules. Those are therefore
# checked on the kernel side.
#
# Advanced expressions and redirect statements 
# (parameter and return value modifications) 
# are splitted into two parts.
# - A seccomp rule activating the tracer
# - C-Source implementing the checks and modifications
#
# The Module allows to define global rules  or 
# for specific systemcalls.
# Global rules are based on the group specifiers of arguments.
# If the filename parameter of open and chdir are both linked 
# to the group "path", a global rule will affect both
# 
# -----------------------------------------------------------------
# Version: 1.0
# -----------------------------------------------------------------
# 01.04.2018:       schwerem        Version 1.0 implemented
# -----------------------------------------------------------------
#
# TODO:
#  - Cleanup some seccomp rules for the tracer side
#  - More debug options which allow to get information
#    about the rule which has terminated / halted the application
#    and not only the systemcall or its parameters
#  - Advanced error messages for invalid file formats
#
###################################################################

from libs.SecCParser import CParser, FieldNotFoundError
from libs.SecInfParser import SecInfParser
from libs.SecRegexBuilder import SecRegexBuilder
from libs.SecRules import SeccompRule, ExpressionRule
from libs.SecCWriter import SecCWriter
from configparser import ConfigParser
from enum import Enum
import argparse
import os


parser = argparse.ArgumentParser(description="Seccomp generation framework.\nGenerates c based seccomp rules and source to check and intercept system calls.")
parser.add_argument("--conf", type=str, default="configs/sec_syscalls_conf.c", help="System call configuration file (default: sec_syscalls_conf.c)")
parser.add_argument("--rule", type=str, default="sec_rules.ini", help="Permission rule definitions / actions (default: sec_rules.ini")
parser.add_argument("--tmpl", type=str, default="configs/source_templates.ini", help="Source templates for the builder (default: source_templates.ini)")
parser.add_argument("-o", type=str, default="out", help="Output dir for the generated source files (default: out)")
args = parser.parse_args()

OUTPUT_DIR = args.o + "/"

try:
    os.makedirs(OUTPUT_DIR)
except FileExistsError as e:
    pass;

# parse the configuration file for the sec syscalls
config_funcdefs = CParser();
config_funcdefs.read(args.conf);

# parse the configuration file for the security rules
rules_config = SecInfParser();
rules_config.read(args.rule);

# load the source template file 
templates = ConfigParser(interpolation=None);
templates.read(args.tmpl);

# defines the type of a code line
class LocType(Enum):
    OVERWRITE    = 1
    PID          = 2
    SKIP         = 3
    RULE_CHECK   = 4
    CODE         = 5
    DEBUG_BEGIN  = 6
    DEBUG_END    = 7
    LOG_DEBUG    = 8
    LOG_INFO     = 9
    LOG_CRIT     = 10
    LOG_ALERT    = 11

# Description:
# loads a specific template from the source_template.ini file
# if debug is enabled, it first looks if a debug version is available
#
# Parameter:
# template: name of the template
#
# Return:
# template as string
def getSourceTemplate(template):
    source = None;

    if rules_config.debugEnabled() == True:
        source = templates["Debug"].get(template, None);

    if source == None:
        source = templates["Productive"].get(template, None);

    return source;

# Description:
# creates the basic seccomp rules based on the 
# syscall {action} and tracer {action} rules
# which basically allow, terminate, skip or modify syscalls
# by default
#
# Parameter:
# seccomp_rules: list of seccomp rules
# seccomp_rules_tracer: list of tracer specific seccomp rules
#
# Return:
# The rules are added to the passed parameter lists
def fetchBasicSeccompRules(seccomp_rules, seccomp_rules_tracer):
    actions = ["allow", "terminate", "skip", "modify"];

    for action in actions:
        systemcalls = rules_config.getSystemcallsForAction(action);
        for call in systemcalls:
            addPermissionRule(seccomp_rules, None, call, action = action, _checks = [], primitive = True)

        systemcalls = rules_config.getSystemcallsForAction(action, for_tracer = True);
        for call in systemcalls:
            addPermissionRule(seccomp_rules_tracer, None, call, action = action, _checks = [], primitive = True)
        

    return seccomp_rules;

# Description:
# Adds an item to a dict holding lists as values
# if a list for a specific does not exist,
# it will be created
#
# Parameter:
# _dict: Dictionary to modify
# _key: key value of the dictionary
# _value: value to add to the list of the key
#
# Return:
# the _dict parameter is modified directly
def addItemToDictKeyList(_dict, _key, _value):
    if not _key in _dict:
        _dict[_key] = [];
    _dict[_key].append(_value);

# Description:
# Transforms the passeed group or field name into the argument name
# also expressions like rlim_group->rlim_max are transformed to for
# example rlim->rlim_max
#
# Parameter:
# syscall: Name of the system call
# group_field: Either the group or field name or as a struct access line
#
# Return:
# The argument/field name
def transformGroupToFieldName(syscall, group_field):
    if group_field == None:
        return None

    parts = group_field.split("->")
    parts[0] = config_funcdefs.getArgumentInfo(syscall, parts[0])["name"]

    return "->".join(parts);

# Description:
# Reformulates a complex expression to understand constructs like 
# start_with, end_with
#
# Parameter:
# syscall: Name of the system call
# complex_statement: C based statement (form rule)
#
# Return:
# Modified c expression
def reformulateComplexExpression(syscall, complex_statement):
    complex_statement = transformGroupToFieldNameInExpression(syscall, complex_statement)

    if complex_statement == None:
        return None

    # reformat the starts_with and ends_with statements so they point to the corresponding c_function
    while "starts_with" in complex_statement or "ends_with" in complex_statement:
        check = complex_statement;
        transition = None;
        if "=>" in complex_statement:
            check = complex_statement.split("=>")[0]
            transition = complex_statement.split("=>")[1]

        reg = SecRegexBuilder();
        reg.scanCVariableName("variable")
        reg.ignoreSpaces();
        reg.scanCustom("not", "not", quantifier = "?");
        reg.ignoreSpaces();
        reg.scanCustom("is_dir", "dir_", quantifier = "?");
        reg.scanCustom("is_fdpath", "fd_path_", quantifier = "?");
        reg.scanCustom("type", "starts|ends");
        reg.expectString("_with\(")
        reg.scanString("string")
        reg.expectString("\)")
        m = reg.execute(complex_statement)  

        par = config_funcdefs.getArgumentInfo(syscall, m.group("variable").strip())
        operator = "" if m.group("not") is None else "!";
        string = m.group("string").strip()
        size = getParameterSizeExpression(par);
        method = ""
        if m.group("is_fdpath"):
            method = getSourceTemplate("fd_path_" + m.group("type").strip() + "_with_check") 
        else:
            method = getSourceTemplate(m.group("type").strip() + "_with_check") if transition is None else getSourceTemplate(m.group("type").strip() + "_with_replace") 


        method = method.replace("{reference}", string)
        method = method.replace("{field}", par["name"])
        method = method.replace("{length}", size)
        method = method.replace("{pid}", "pid")
        method = method.replace("{is_dir}", "false" if m.group("is_dir") is None else "true")

        if not transition:
            method = method.replace("{negate_operator}", operator)

            complex_statement = complex_statement[:m.span()[0]] + method + complex_statement[m.span()[1]:] 
        else:
            if m.group("is_fdpath"):
                print("Changing the path of file descriptors is currently not supported. Abort Process.")
                exit()
            reg = SecRegexBuilder();
            reg.ignoreSpaces();
            reg.scanString("string")
            m = reg.execute(transition) 

            method = method.replace("{new_string}", m.group("string").strip())
            method = method.replace("{nr}", str(par["argument_nr"]))
            method = method.replace("{is_out}", "true" if par["out"] == True else "false")
            complex_statement = method; 

    return complex_statement;

# Description:
# Parses the information of a redirection rule
# and creates the necessary seccomp and expression rules
#
# either the _check or (_from with _op) or _expression field has to be passed
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
# expression_rules: list holding the expression rules
# syscall: Name of the system call
# _field: field which is redirected
# _to: new value of the field
# _check: check expression which has to be fulfilled before redirection
# _from: defines a single value, the field has to be checked against before redirection
# _op: defines the comparison operator for the _from parameter
# _exprssion: defines a complex expression for the check part
# _permissions: defines the permission flags of the rule
#
# Return:
# Adds the rules directly to the corresponding lists
def addRedirectionRule(seccomp_rules, expression_rules, syscall, _field, _to, _check = None, _from = None, _op = None, _expression = None, _permissions = None):
    _op = _op if not _op is None else "=="
    _field = transformGroupToFieldName(syscall, _field);
    _check = transformGroupToFieldNameInExpression(syscall, _check)
    _permissions = None if not _permissions else _permissions

    if not _check is None:
        if not "||" in _check and not "(" in _check and not "->" in _check and _permissions is None:
            seccomp_rules.append(                            SeccompRule(syscall,    "seccomp", "modify", transformPrimitiveChecksToSeccompChecks(syscall, _check)))
        else:
            seccomp_rules.append(                            SeccompRule(syscall,    "seccomp", "modify", []))

        # generate expression rule
        addItemToDictKeyList(expression_rules, syscall,      ExpressionRule(syscall, "expression_c", "redirect", _field, _check, _to, _permissions))
    elif not _from is None:
        # generate seccomp rule to activate ptrace (specific seccomp rule or general if non primitive type)
        if not "->" in _field and _permissions is None:
            seccomp_rules.append(                            SeccompRule(syscall,    "seccomp", "modify", [{"field": _field, "operator": _op, "value": _from}]))
        else:
            seccomp_rules.append(                            SeccompRule(syscall,    "seccomp", "modify", []))
        # generate expression rule
        addItemToDictKeyList(expression_rules, syscall,      ExpressionRule(syscall, "basic_c", "redirect", _field, "{:s} {:s} {:s}".format(_field, _op, _from), _to, _permissions))
    elif not _expression is None:
        seccomp_rules.append(                                SeccompRule(syscall,    "seccomp", "modify", []))
        addItemToDictKeyList(expression_rules, syscall,      ExpressionRule(syscall, "expression_c", "redirect", _field, None, _expression, _permissions))
    else:
        print("Error in addRedirectionRule: Neither the parameter _check or _from is defined. At least one must be set")
        exit()

# Description:
# Parses the information of a permission rule (terminate, allow or skip)
# and creates the necessary seccomp and expression rules
#
# either the (_checks with primitive) or (_field with _from with _op with primitive) has to be passed
#
# if an expression has a complex criterion which can not be broken down
# into a simple seccomp expression to trigger modify,
# a general modify rule is created for the system call
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
# expression_rules: list holding the expression rules
# syscall: Name of the system call
# action: action to execute (terminate, skip or allow)
# _field: field which is redirected
# _op: defines the comparison operator for the _from parameter
# _value: value the field should be checked against
# primitive: defines if the _checks parameter consists of primitive parameters (no pointers))
# _complex_statement: defines a complex statement for the rule check (c-based construct)
# _permissions: defines the permission flags of the rule
#
# Return:
# Adds the rules directly to the corresponding lists
def addPermissionRule(seccomp_rules, expression_rules, syscall, action, _field = None, _op = None, _value = None, primitive = False, _checks = None, _complex_statement = None, _permissions = None):
    _field = transformGroupToFieldName(syscall, _field);
    _complex_statement = reformulateComplexExpression(syscall, _complex_statement)
    _permissions = None if not _permissions else _permissions

    if _complex_statement is None:
        _checks = _checks if not _checks is None else [{"field": _field, "operator": _op, "value": _value}]
        if primitive == True and _permissions is None:      
            seccomp_rules.append(                            SeccompRule(syscall,    "seccomp", action, _checks))
        else:
            seccomp_rules.append(                            SeccompRule(syscall,    "seccomp", "modify",  []))

            check_list = []
            for chk in _checks:
                field = transformGroupToFieldName(syscall, chk["field"]);
                check_list.append(field + " " + chk["operator"] + " " + chk["value"])
            addItemToDictKeyList(expression_rules, syscall,  ExpressionRule(syscall, "basic_c", action, _field, " || ".join(check_list), None, _permissions))
    else:   
        seccomp_rules.append(                                SeccompRule(syscall,    "seccomp", "modify",  []))
        addItemToDictKeyList(expression_rules, syscall,      ExpressionRule(syscall, "expression_c", action, _field, _complex_statement, None, _permissions))

# Description:
# transforms the group names in an expression to the corresponding argument names of a system call
# contrary to transformGroupToFieldName, the transformation is done for a complex
# c based expression
#
# if the expression is too complex, all group names in the expression are
# replaced by the replace function to the corresponding field
# this may lead to unwanted modifications within strings,...
#
# Parameter:
# syscall: Name of the system call
# expression: c based expression to modify
# primitive_change: does the basic replace without trying to parse the expression
#
# Return:
# modified c expression
def transformGroupToFieldNameInExpression(syscall, expression, primitive_change = False):
    if expression == None:
        return None

    if "(" in expression or "||" in expression or primitive_change:
        groups = config_funcdefs.getGroupFieldLink(syscall);
        for group in groups:
            expression = expression.replace(group["group"] + " ", group["field"] + " ");
            expression = expression.replace(group["group"] + "-", group["field"] + "-");
            expression = expression.replace(group["group"] + "=", group["field"] + "=");
            expression = expression.replace(group["group"] + ">", group["field"] + ">");
            expression = expression.replace(group["group"] + "<", group["field"] + "<");
    else:
        new_checks = []
        checks = expression.split("&&");
        for check in checks:
            reg = SecRegexBuilder();
            reg.scanCVariableName("field")
            reg.ignoreSpaces();
            reg.scanOperator("operator");
            reg.ignoreSpaces();
            reg.scanAny("value")
            m = reg.execute(check)  

            field  = transformGroupToFieldName(syscall, m.group("field").strip());                          
            new_checks.append("{:s} {:s} {:s}".format(field, m.group("operator").strip(), transformGroupToFieldNameInExpression(syscall, m.group("value").strip(), primitive_change = True)))
        expression = " && ".join(new_checks)

    return expression;

# Description:
# transforms basic check expressions with primitive datatypes to seccomp clause checks
# only supports basic c-expressions not containing pointer expressions
# the checks only support the concatenation of && checks
#
# Parameter:
# syscall: Name of the system call
# value: c-based expression consisting of && criterias
#
# Return:
# modified c expression
def transformPrimitiveChecksToSeccompChecks(syscall, value):
    checks = [];

    if not "||" in value and not "(" in value: 
        for check in value.split("&&"):
            reg = SecRegexBuilder();
            reg.scanCVariableName("field")
            reg.ignoreSpaces();
            reg.scanOperator("operator");
            reg.ignoreSpaces();
            reg.scanValue("value")
            m = reg.execute(check)  

            field  = transformGroupToFieldName(syscall, m.group("field").strip());
                                
            checks.append({"field": field, "operator": m.group("operator").strip(), "value": m.group("value").strip()})

    return checks;

# Description:
# Fetches and parses all complex expression rules
# depending on the action and the rule structure,
# corresponding seccomp and expression (c-based) rules
# are generated
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
# expression_rules: list holding the expression rules
#
# Return:
# modified c expression
def fetchExpressionRules(seccomp_rules, expression_rules):
    sections = rules_config.getSystemcallsForAction("custom")

    for section in sections:
        systemcalls = [section];
        if section == "Global":
            systemcalls = list(filter(lambda s: s != "Global", sections));

        for syscall in systemcalls:
            # basic rule creation
            basicRules = rules_config.getBasicRules(section);
            for rule in basicRules:
                permissions = None
                if not config_funcdefs.getPermissionFlag(syscall) is None:
                    permissions = rule["rights"]

                try:
                    _type = "seccomp" if config_funcdefs.isFieldPrimitive(syscall, rule["field"]) else "basic_c"
                    if rule["action"] == "redirect":
                        for value in rule["values"]:
                            _from = value.split("=>")[0].strip()
                            _to = value.split("=>")[1].strip()

                            reg = SecRegexBuilder();
                            reg.scanOperator("op", optional=True)
                            reg.ignoreSpaces();
                            reg.scanValue("value");
                            m = reg.execute(_from)

                            _op = "==" if m.group("op") == None else m.group("op").strip()
                            _from_value = m.group("value").strip()

                            # add redirection rule
                            if not "(" in value:
                                addRedirectionRule(seccomp_rules, expression_rules, syscall, rule["field"], _to, _from = _from_value, _op = _op, _permissions = permissions)
                            else:
                                value = rule["field"] + " " + value;
                                value = reformulateComplexExpression(syscall, value);
                                addRedirectionRule(seccomp_rules, expression_rules, syscall, rule["field"], None, _expression = value, _permissions = permissions)
                    else:
                        non_primitive_checks = []
                        for value in rule["values"]:
                            if "&&" in value or "||" in value:
                                print("The basic Rule expression type: <field action:    check> does not allow complex expressions with && or ||.")
                                print("Use the advanced Rule expression type instead. Example: <action:  field op check && field op check ....>")
                                print("Abort Process")
                                exit()

                            if not "(" in value:
                                reg = SecRegexBuilder();
                                reg.scanOperator("op", optional=True)
                                reg.ignoreSpaces();
                                reg.scanValue("value");
                                m = reg.execute(value)

                                _op = "==" if m.group("op") == None else m.group("op").strip()
                                _value = m.group("value").strip()
                                _primitive = True if not "->" in rule["field"] else False

                                if _primitive == False:
                                    non_primitive_checks.append({"field": rule["field"], "operator": _op, "value": _value})
                                else:
                                    addPermissionRule(seccomp_rules, expression_rules, syscall, action = rule["action"], _field = rule["field"], _op = _op, _value = _value, primitive = _primitive, _permissions = permissions)
                            else:
                                value = rule["field"] + " " + value;
                                addPermissionRule(seccomp_rules, expression_rules, syscall, action = rule["action"], _complex_statement = value, _permissions = permissions)

                        # add permission rule
                        if non_primitive_checks:
                            addPermissionRule(seccomp_rules, expression_rules, syscall, action = rule["action"], _field = rule["field"], _op = _op, _value = _value, primitive = False, _checks = non_primitive_checks, _permissions = permissions)
                except FieldNotFoundError as e:
                    if section == "Global":
                        pass
                        continue
                    else:
                        print(e.message)
                        exit()


            # expression rule creation
            expressionRules = rules_config.getExpressionRules(section);

            for rule in expressionRules:
                permissions = None
                if not config_funcdefs.getPermissionFlag(syscall) is None:
                    permissions = rule["rights"]

                try:
                    if rule["action"] == "redirect":
                        _type = "expression_c"
                        for value in rule["values"]:
                            if ":" in value:
                                _check = value.split(":")[0].strip()
                                _to = value.split(":")[1].strip()
                                _field = _to.split("=>")[0].strip()
                                _to_value = _to.split("=>")[1].strip()

                                if "(" in _check:
                                    _check = reformulateComplexExpression(syscall, _check);

                                # add redirection rule
                                addRedirectionRule(seccomp_rules, expression_rules, syscall, _field, _to_value, _check = _check, _permissions = permissions)
                            else:
                                _from = value.split("=>")[0].strip()
                                _to = value.split("=>")[1].strip()

                                # check if the new value is a string (if yes, handle it different)
                                if _to[0] == "\"":
                                    reg = SecRegexBuilder();
                                    reg.scanCVariableName("field")
                                    m = reg.execute(value)  

                                    field = m.group("field").strip();
                                    value = reformulateComplexExpression(syscall, value);   

                                    addRedirectionRule(seccomp_rules, expression_rules, syscall, field, None, _expression = value, _permissions = permissions)
                                else:
                                    reg = SecRegexBuilder();
                                    reg.scanCVariableName("field")
                                    reg.ignoreSpaces();
                                    reg.scanOperator("operator");
                                    reg.ignoreSpaces();
                                    reg.scanValue("value")
                                    m = reg.execute(value)

                                    # etract fields
                                    _op = m.group("operator").strip();
                                    _field = m.group("field").strip();
                                    _value = m.group("value").strip();

                                    # add redirection rule
                                    addRedirectionRule(seccomp_rules, expression_rules, syscall, _field, _to, _from = _value, _op = _op, _permissions = permissions)

                    else:       
                        for value in rule["values"]:
                            if "->" in value:
                                addPermissionRule(seccomp_rules, expression_rules, syscall, action = rule["action"], _complex_statement = value, _permissions = permissions)
                            else:
                                if not "||" in value and not "(" in value: 
                                    _type = "basic_c"
                                    checks = transformPrimitiveChecksToSeccompChecks(syscall, value)

                                    # add permission rule
                                    addPermissionRule(seccomp_rules, expression_rules, syscall, action = rule["action"], primitive = True, _checks = checks, _permissions = permissions)
                                else:
                                    # add permission rule
                                    addPermissionRule(seccomp_rules, expression_rules, syscall, action = rule["action"], _complex_statement = value, _permissions = permissions)
                except FieldNotFoundError as e:
                    if section == "Global":
                        pass
                        continue
                    else:
                        print(e.message)
                        exit()

# Description:
# removes duplicate rules from the seccomp rule set
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
#
# Return:
# new seccomp_rules list without duplicates
def removeDublicateSeccompRules(seccomp_rules):
    _set = set(seccomp_rules)
    return list(_set)

# Description:
# remove specific modifications if a general exists
# if for example a rule exists for modify socket
# when the domain is AF_UNIX and a modify socket
# rule exists without any checks.
# the rule with the checks is deleted.
# (performance improvement due to reduction of rules)
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
#
# Return:
# new seccomp_rules list without redundancies
def removeSpecificSeccompModifyRulesIfRedundant(seccomp_rules):
    general_rules = list(filter(lambda rule: not rule.hasParameterChecks() and rule.getAction() == "modify", seccomp_rules))
    new_rules = []
    for rule in seccomp_rules:
        addRule = True;
        for gr in general_rules:
            if rule.getSyscall() == gr.getSyscall() and rule.getAction() == "modify" and rule.hasParameterChecks():
                addRule = False;
        if addRule:
            new_rules.append(rule)

    return new_rules;

# Description:
# cleanes up the seccomp rules to remove unnecessary constructs and duplicates
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
#
# Return:
# new seccomp_rules list without redundancies and duplicates
def cleanupSeccompRules(seccomp_rules):
    seccomp_rules = removeDublicateSeccompRules(seccomp_rules)
    seccomp_rules = removeSpecificSeccompModifyRulesIfRedundant(seccomp_rules)

    return seccomp_rules;

# Description:
# Generates the c-source for a list of SeccompRules
#
# Parameter:
# rules: list of seccomp rules
# comment: comment to add above the generated rules
# for_tracer: defines if the rules are generated for the tracer instance
#
# Return:
# the c-code as a list of strings
def generateSeccompRuleCode(rules, comment, for_tracer = False):
    comparators = {"==": "EQ", "<": "LT", "<=": "LE", ">": "GT", ">=": "GE", "!=": "NE"};

    basic_rule_template = getSourceTemplate("seccomp_basic_rule");
    argument_rule_template = getSourceTemplate("seccomp_argument_rule");
    code_lines = []

    if rules:
        code_lines.append(comment)
        for rule in rules:
            action_name = "" if not for_tracer else "_tracer";
            action_str = getSourceTemplate("seccomp_{:s}{:s}".format(rule.getAction(), action_name)).replace("{syscall_nr}", "SCMP_SYS({:s})".format(rule.getSyscall())).replace("{errorcode}", "EPERM");

            if rule.hasParameterChecks():
                checks = rule.getParameterChecks();
                argument_template = getSourceTemplate("seccomp_argument")

                args = []
                for check in checks:
                    arg_str = argument_template.replace("{nr}", str(config_funcdefs.getArgumentNr(rule.getSyscall(), check["field"]) - 1)).replace("{comparator}", comparators[check["operator"]]).replace("{value}", check["value"])
                    args.append(arg_str)

                rule_str = argument_rule_template.replace("{syscall_nr}", "SCMP_SYS({:s})".format(rule.getSyscall())).replace("{action}", action_str).replace("{count}", str(len(checks))).replace("{argument}", ",".join(args));
                code_lines.append(rule_str)
            else:
                rule_str = basic_rule_template.replace("{syscall_nr}", "SCMP_SYS({:s})".format(rule.getSyscall())).replace("{action}", action_str);
                code_lines.append(rule_str)

    return code_lines;

# Description:
# Generates the c-source for the initialization of the seccomp routine
# for the client and the tracer
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
# seccomp_rules_tracer: list holding the seccomp rules for the tracer instance
#
# Return:
# the c-code as a list of strings
def generateSeccompInitRoutine(seccomp_rules, seccomp_rules_tracer = None):
    init_template = getSourceTemplate("seccomp_init");
    code_lines = []
    for_tracer = False if seccomp_rules_tracer is None else True

    # append general rules
    for action in ["allow", "terminate", "skip", "modify"]:
        general_rules = list(filter(lambda r: r.getAction() == action and not r.hasParameterChecks(), seccomp_rules));
        specific_rules = list(filter(lambda r: r.getAction() == action and r.hasParameterChecks(), seccomp_rules));

        if for_tracer:
            general_rules_tracer = list(filter(lambda r: r.getAction() == action and not r.hasParameterChecks() and r not in seccomp_rules, seccomp_rules_tracer));
            code_lines.extend(generateSeccompRuleCode(general_rules_tracer, "// Add general tracer {:s} rules".format(action), for_tracer = for_tracer))

        code_lines.extend(generateSeccompRuleCode(general_rules,  "// Add general {:s} rules".format(action), for_tracer = for_tracer))
        code_lines.extend(generateSeccompRuleCode(specific_rules, "// Add specific {:s} rules".format(action), for_tracer = for_tracer))

    # append default rules
    defaults = rules_config.getDefaultActions();
    default_rules = []
    for default in defaults:
        addPermissionRule(default_rules, None, default["syscall"], action = default["action"], primitive = True, _checks = []);
    code_lines.extend(generateSeccompRuleCode(default_rules, "// Add default actions for custom system calls", for_tracer = for_tracer))

    action_name = "" if not for_tracer else "_tracer";
    default_action = getSourceTemplate("seccomp_{:s}{:s}".format(rules_config.getSeccompDefault(for_tracer = for_tracer), action_name)).replace("{syscall_nr}", "0x00000000")
    
    init_code = init_template.replace("{rules}", "\n".join(code_lines)).replace("{syscall_default_action}", default_action).replace("{instance}", "Client" if not for_tracer else "Tracer" )
    return init_code.split("\n");

# Description:
# Generates the source file for the seccomp rules check
# it therefore collects the includes, the c-source
# and the header-file
#
# Parameter:
# seccomp_rules: list holding the seccomp rules
# seccomp_rules_tracer: list holding the seccomp rules for the tracer instance
# file_name: nime of the source/header file
def generateSeccompRulesSource(seccomp_rules, seccomp_rules_tracer, file_name):
    includes = getSourceTemplate("seccomp_inlucde").split(",");
    routineClient = generateSeccompInitRoutine(seccomp_rules);
    routineTracer = generateSeccompInitRoutine(seccomp_rules, seccomp_rules_tracer = seccomp_rules_tracer);
    includes.append("")
    includes.append("\"{:s}.h\"".format(file_name));
    includes.append("\"sec_ptrace_lib.h\"");

    # collect includes from modified rules
    rule_include = []
    for syscall in set(map(lambda r: r.getSyscall(), filter(lambda r: r.hasParameterChecks(), seccomp_rules))):
        headers = config_funcdefs.getSyscallHeaders(syscall)
        for h in headers:
            includes.append("<" + h + ">");
    includes = set(includes)

    c_source = []
    for include in includes:
        if len(include) > 0:
            c_source.append("#include {:s}".format(include.strip()))
    c_source.append("")   
    c_source.extend(routineClient)
    c_source.extend(routineTracer)
    SecCWriter().exportCode(OUTPUT_DIR + file_name + ".c", c_source);

    h_source = []
    h_source.append("#ifndef {:s}_H".format(file_name.upper()))
    h_source.append("#define {:s}_H".format(file_name.upper()))
    h_source.append("")
    h_source.append("void loadClientSeccompRules();")
    h_source.append("void loadTracerSeccompRules();")
    h_source.append("")
    h_source.append("#endif //{:s}_H".format(file_name.upper()))
    SecCWriter().exportCode(OUTPUT_DIR + file_name + ".h", h_source);

# Description:
# Detects the type of the code line to distinguish
# between standard c-code and macros leading
# to a sophisticated parsing and modification
#
# Parameter:
# line: c-code line
#
# Return:
# LocType defining the type of the code line
def getLocType(line):
    if "OVERWRITE(" in line:
        return LocType.OVERWRITE;
    elif "__PID" in line:
        return LocType.PID;
    elif "SKIP_SYSTEMCALL()" in line:
        return LocType.SKIP;
    elif "CHECK_RULES()" in line:
        return LocType.RULE_CHECK;
    elif "DEBUG_BEGIN()" in line:
        return LocType.DEBUG_BEGIN;
    elif "DEBUG_END()" in line:
        return LocType.DEBUG_END;
    elif "LOG_ALERT" in line:
        return LocType.LOG_ALERT;
    elif "LOG_DEBUG" in line:
        return LocType.LOG_DEBUG;
    elif "LOG_CRIT" in line:
        return LocType.LOG_CRIT;
    elif "LOG_INFO" in line:
        return LocType.LOG_INFO;
    else:
        return LocType.CODE;

# Description:
# Creates information for a size specifier of a
# specific system call parameter
#
# There are the following cases
#  - is not pointer:        sizeof({datatyle})
#  - is pointer:
#    - lenth not defined:   sizeof({datatyle})
#    - length defined:
#      - strlen in length:  strlen({variable})
#      - else:              {size_field}
#
# {size_field} means, that a parameter size can
# depend on a second parameter
#
# Parameter:
# par: argument info of the system call
#
# Return:
# size expression
def getParameterSizeExpression(par):
    if par["pointer"] == True:
        if not "length" in par:
            size = "sizeof({:s})".format(par["datatype"]);
        else: 
            if "strlen" in par["length"]:
                size = par["length"].replace("strlen", "strlen({:s})".format(par["name"]))
            else:
                size = par["length"];
    else:
        size = "sizeof({:s})".format(par["datatype"]);

    return size;

# Description:
# Generates the source code for the OVERWRITE macro
# 
# Overwrite is parsed as followed:
# - overwrite return:   modifyReturnValue(pid, {newval})
# - else:   
#   - is pointer:
#     - is out:         modifyReturnParameter(pid, ...)
#     - else:           modifyParameter(pid, ...)
#   - else:             modifyPrimitiveParameter(pid, ...)        
#
# is out specifies, if the parameter is written into 
# a buffer of the client application. Best example herefore
# is the system call getcwd where the first parameter buf
# defines a location on the user space of the client app    
#
# Parameter:
# line: c-code line
# funcinfo: informations to the system call
#
# Return:
# c-code as string
def generateEmulatorOverwriteMacro(line, funcinfo):
    reg = SecRegexBuilder();
    reg.skipRandom();
    reg.expectString("OVERWRITE\(");
    reg.scanCVariableName("target");
    reg.findString(",", skip_only_spaces = True);
    reg.scanExpression("source");
    reg.expectString("\)");
    m = reg.execute(line)

    target = m.group("target").strip()
    source = m.group("source").strip()

    src = ""
    if target == "return":
        src = "modifyReturnValue(pid, {:s});".format(source);
    else:
        par = config_funcdefs.getArgumentInfo(funcinfo["systemcall"], target)
        size = getParameterSizeExpression(par)
        if par["pointer"] == True:
            if par["out"] == True:
                src = "modifyReturnParameter(pid, PAR{:d}, {:s}, {:s});".format(par["argument_nr"], source, size)
            else:
                src = "modifyParameter(pid, PAR{:d}, {:s}, {:s});".format(par["argument_nr"], source, size)
        else:
            src = "modifyPrimitiveParameter(pid, PAR{:d}, {:s});".format(par["argument_nr"], source)

    return src;

# Description:
# Generates the if checks for the permission checks of a path flag
# 
# All permission checks are performed on the parameter with
# the group tag called permission_flag
#  
# Parameter:
# fule: Rule object (either PermissionRule or ExpressionRule)
# funcinfo: informations to the system call
#
# Return:
# c-code as string
def generatePermissionCheckStatement(rule, funcinfo):
    permissions = rule.getPermissions();
    if permissions is None:
        return None

    field = config_funcdefs.getPermissionFlag(funcinfo["systemcall"])
    check_template = getSourceTemplate("rule_permission_check_rw")
    source = ""

    if "r" in permissions and "w" in permissions:
        source = "{:s}".format(                check_template.replace("{variable}", field).replace("{flag}", "O_RDONLY"))
        source = "{:s} || {:s}".format(source, check_template.replace("{variable}", field).replace("{flag}", "O_WRONLY"))
        source = "{:s} || {:s}".format(source, check_template.replace("{variable}", field).replace("{flag}", "O_RDWR"))
    elif "r" in permissions:
        source = "{:s}".format(                check_template.replace("{variable}", field).replace("{flag}", "O_RDONLY"))
        source = "{:s} || {:s}".format(source, check_template.replace("{variable}", field).replace("{flag}", "O_RDWR"))
    elif "w" in permissions:
        source = "{:s}".format(                check_template.replace("{variable}", field).replace("{flag}", "O_WRONLY"))
        source = "{:s} || {:s}".format(source, check_template.replace("{variable}", field).replace("{flag}", "O_RDWR"))

    check_template = getSourceTemplate("rule_permission_check")
    if "c" in permissions:
        source = "{:s} || {:s}".format(source, check_template.replace("{variable}", field).replace("{flag}", "O_CREAT"))
    if "x" in permissions:
        source = "{:s} || {:s}".format(source, check_template.replace("{variable}", field).replace("{flag}", "O_EXEC"))

    source = source.strip().strip("||").strip()
    return source;

# Description:
# Generates the c-code a list of systemcalls within 
# the emulator based on the sec_syscalls_conf.c file. 
#
# Parameter:
# line: c-code line
# expression_rules: List of expression rules to generate the source for
# funfinfo: information structure about the system call
#
# Return:
# c-code as list of strings
def generateEmulatorRuleCheck(line, expression_rules, funcinfo):
    source = []
    syscall_name = funcinfo["systemcall"][4:];

    # check if rules were defined for the specific system call
    if not syscall_name in expression_rules:
        return [];

    # get default action
    default_action = rules_config.getDefaultActions(syscall = syscall_name)
    if not default_action:
        print("There is no default action defined for the systemcall: {:s}.\nAbort Process.".format(syscall_name))
        exit()

    # generate initialization
    check_init_src = getSourceTemplate("rule_check_init").replace("{default_syscall_action}", "SEC_ACTION_" + default_action.upper());
    source.extend(check_init_src.split("\n"))
    source.append("")

    # generate specific redirection rules
    for rule in list(filter(lambda r: r.getAction() == "redirect", expression_rules[syscall_name])):
        template = getSourceTemplate("rule_check_if")

        field = rule.getField();
        if "->" in field:
            field = field.split("->")[0]

        permission_check = generatePermissionCheckStatement(rule, funcinfo);

        rule_src = ""
        if not rule.getCheck() is None: 
            par = config_funcdefs.getArgumentInfo(rule.getSyscall(), rule.getField());
            code = ""
            if rule.getNewValue()[0] == "\"":
                code = getSourceTemplate("rule_set_code_string");
                code = code.replace("{string}", rule.getNewValue())
                code = code.replace("{nr}", str(par["argument_nr"]))
                code = code.replace("{is_out}", "true" if par["out"] == True else "false")
            else:
                par = config_funcdefs.getArgumentInfo(rule.getSyscall(), rule.getField());
                code = getSourceTemplate("rule_set_code_val");
                code = code.replace("{variable}", rule.getField())
                code = code.replace("{new_value}", transformGroupToFieldNameInExpression(rule.getSyscall(), rule.getNewValue(), primitive_change = True))
                code = code.replace("{overwrite}", generateEmulatorOverwriteMacro("OVERWRITE({:s}, {:s})".format(field, field), funcinfo))

            clause = rule.getCheck()
            if not permission_check is None:
                clause = "({:s}) && ({:s})".format(rule.getCheck(), permission_check)
            rule_src = template.replace("{clause}", clause);
            rule_src = rule_src.replace("{rule_action}", "SEC_ACTION_ALLOW")
            rule_src = rule_src.replace("{code}", code);
            rule_src = rule_src.replace("\n\n", "\n")
            rule_src = rule_src.strip() 
        else:
            if permission_check is None:
                rule_src = rule.getNewValue()
            else:
                rule_src = getSourceTemplate("rule_permission_if").replace("{clause}", permission_check).replace("{code}", rule.getNewValue())

        source.extend(rule_src.split("\n"))

    # generate specific permission rules
    source.append("")
    first_rule = True;
    for rule in list(filter(lambda r: r.getAction() != "redirect", expression_rules[syscall_name])):
        permission_check = generatePermissionCheckStatement(rule, funcinfo);
        template = getSourceTemplate("rule_check_if") if first_rule else getSourceTemplate("rule_check_elseif")

        clause = rule.getCheck()
        if not permission_check is None:
            clause = "({:s}) && ({:s})".format(rule.getCheck(), permission_check)
        rule_src = template.replace("{clause}", clause);
        rule_src = rule_src.replace("{code}", "");
        rule_src = rule_src.replace("{rule_action}", "SEC_ACTION_" + rule.getAction().upper())
        rule_src = rule_src.replace("\n\n", "\n")
        rule_src = rule_src.strip()

        source.extend(rule_src.split("\n"))
        first_rule = False;

    # generate rule execution
    source.append("")
    source.append(getSourceTemplate("rule_check_execute"))

    return source

# Description:
# Generates the parameter loader part of the multiplexer.
# This is needed to read the data from the traced application
# and pass them to the emulated systemcalls of the tracer
#
# Parameter:
# par: parameter info structure
#
# Return:
# c-code as string
def generateMultiplexerParameterLoader(par):
    ptr = "*" if par["pointer"] == True else "";

    source = "";
    size = getParameterSizeExpression(par)

    # check if parameter is a string
    if "strlen" in size:
        source = "readTerminatedString(pid, PAR{:d})".format(par["argument_nr"]);
    elif "length" in par:
        source = "readData(pid, PAR{:d}, {:s})".format(par["argument_nr"], size);
    else:
        if par["pointer"]:
            source = "readData(pid, PAR{:d}, {:s})".format(par["argument_nr"], size);
        else:
            source = "({:s})readInt(pid, PAR{:d})".format(par["datatype"], par["argument_nr"]);

    definition = "{:s} {:s}{:s} = {:s};".format(par["datatype"], ptr, par["name"], source);
    return definition;

# Description:
# Parses the logging macro to write log entries
#
# Parameter:
# locType: Type of the code line
# line. c-code line
#
# Return:
# c-code as list of strings
def parseLoggingAction(locType, line):
    code = []
    level = {LocType.LOG_INFO: "LOG_INFO", LocType.LOG_CRIT: "LOG_CRT", LocType.LOG_DEBUG: "LOG_DEBUG", LocType.LOG_ALERT: "LOG_ALERT"}

    reg = SecRegexBuilder();
    reg.findString(string = level[locType] + "\(", skip_only_spaces = True);
    reg.scanAny("string");
    reg.expectString("\)");
    m = reg.execute(line)

    code.append("writeLog({:s}, {:s});".format(level[locType], m.group("string").strip()))

    return code;


# Description:
# Generates the source for the emulator / 
# c-based check part of the framework for 
# a list of expression rules for a specific
# system call
#
# Outputs are the includes, c-source and
# multiplexer part of the function
#
# Parameter:
# expression_rules: List of expression_rules
# funcinfo: information structure for the system call
#
# Return:
# triple consisting of (includes, c_source and multiplexer)
def generateEmulatorFunction(expression_rules, funcinfo):
    includes = []
    c_source = []
    multiplexer = []

    # generate includes
    if "headers" in funcinfo:
        for header in funcinfo["headers"]:
            includes.append("#include <{:s}>".format(header));

    # generate function prototype
    c_source.append(config_funcdefs.generatePrototype(funcinfo, addpid = True))

    # create empty calls for parameters (in case of compiler flag for unused parameters)
    c_source.append("(void)pid;")
    for key, arginfo in funcinfo["arguments"].items():
        c_source.append("(void){:s};".format(arginfo["name"]))
    c_source.append("")

    # check source
    in_debug_section = False;
    for line in funcinfo["raw"]:
        locType = getLocType(line);
        if locType == LocType.PID:
            line = line.replace("__PID", "pid");
            locType = getLocType(line);

        new_lines = []
        if locType == LocType.OVERWRITE:
            new_lines.append(generateEmulatorOverwriteMacro(line, funcinfo));
        elif locType == LocType.SKIP:
            new_lines.append("invalidateSystemcall(pid);")
        elif locType == LocType.RULE_CHECK:
            new_lines.extend(generateEmulatorRuleCheck(line, expression_rules, funcinfo))
        elif locType == LocType.DEBUG_BEGIN:
            in_debug_section = True;
            if rules_config.debugEnabled():
                new_lines.append("{")
        elif locType == LocType.DEBUG_END:
            in_debug_section = False;
            if rules_config.debugEnabled():
                new_lines.append("}")   
        elif locType == LocType.LOG_INFO or locType == LocType.LOG_CRIT or locType == LocType.LOG_DEBUG or locType == LocType.LOG_ALERT:
            new_lines.extend(parseLoggingAction(locType, line));
        else:
            new_lines.append(line)

        if (in_debug_section and rules_config.debugEnabled()) or in_debug_section == False:
            c_source.extend(new_lines);

    # generate multiplexer source
    template = getSourceTemplate("rule_multiplexer_case");
    template = template.replace("{syscall}", funcinfo["systemcall"])
    template = template.replace("{sec_function}", funcinfo["function"])
    template = template.replace("\n\n", "\n")
    template = template.strip()

    arg_load = []
    cleanup = []
    for i in range(6, 0, -1):
        try:
            arginfo = config_funcdefs.getArgumentInfo(funcinfo["systemcall"], i, field_as_argument_nr = True)
            arg_load.append(generateMultiplexerParameterLoader(arginfo))
            if arginfo["pointer"]:
                cleanup.append("free({:s});".format(arginfo["name"]))
        except FieldNotFoundError as e:
            pass;

    template = template.replace("{param_load}", "\n".join(arg_load))
    template = template.replace("{cleanup}", "\n".join(cleanup))
    template = template.replace("\n\n", "\n")
    template = template.strip("\n")

    params = ["pid"]
    for i in range(1, len(funcinfo["arguments"].items()) + 1):
        arg = config_funcdefs.getArgumentInfo(funcinfo["systemcall"], i, field_as_argument_nr = True)
        params.append(arg["name"]);
    template = template.replace("{sec_function_params}", ", ".join(params))
    multiplexer = template.split("\n")

    return (includes, c_source, multiplexer)

# Description:
# Generates the c-source and h-filefor the 
# emulation / c-based check functions.
# 
# The source is based on the sec_syscalls_conf.c file
#
# Parameter:
# expression_rules: List of expression_rules
# file_name: name of the .c and .h file
def generateEmulatorSource(expression_rules, file_name):
    wrappers = config_funcdefs.getSystemCallWrapperFunctions()

    c_source = []
    includes = ["#include \"sec_ptrace_lib.h\"", "#include \"{:s}\"".format(file_name + ".h")]
    multiplexer = []
    productive_switch_cases = []

    for include in getSourceTemplate("emulator_include").split(","):
        if len(include) > 0:
            includes.append("#include {:s}".format(include.strip()))
        else:
            includes.append("")

    # generate function specific source
    for wrapperfun in wrappers:
        (_includes, _c_source, _multiplexer) = generateEmulatorFunction(expression_rules, wrapperfun);
        includes.extend(_includes)
        c_source.extend(_c_source)
        productive_switch_cases.extend(_multiplexer)

    # filter duplicates
    includes = set(includes)
    includes = list(includes)

    # finish multiplexer
    productive_switch_src = ["switch (syscall_n){"]
    productive_switch_src.extend(productive_switch_cases)
    productive_switch_src.extend(getSourceTemplate("rule_multiplexer_default").split("\n"))
    productive_switch_src.append("}")

    multiplexer.append("void performSystemcall(pid_t pid, int status, int syscall_n){")
    multiplexer.extend(productive_switch_src);
    multiplexer.append("}")

    # generate c_files
    c_file = []
    c_file.extend(includes)
    c_file.append("")
    c_file.extend(c_source)
    c_file.append("")
    c_file.extend(multiplexer)

    SecCWriter().exportCode(OUTPUT_DIR + file_name + ".c", c_file);

    # generate h file
    h_source = []
    h_source.append("#ifndef {:s}_H".format(file_name.upper()))
    h_source.append("#define {:s}_H".format(file_name.upper()))
    h_source.append("")
    h_source.append("#include <unistd.h>")
    h_source.append("")
    h_source.append("void performSystemcall(pid_t pid, int status, int syscall_n);")
    h_source.append("")
    h_source.append("#endif //{:s}_H".format(file_name.upper()))
    SecCWriter().exportCode(OUTPUT_DIR + file_name + ".h", h_source);

# data structures to store the rules
seccomp_rules = []
seccomp_rules_tracer = []
expression_rules = dict()

# add allowed system calls to filter
fetchBasicSeccompRules(seccomp_rules, seccomp_rules_tracer)

# generate seccomp rules with parameter checks
fetchExpressionRules(seccomp_rules, expression_rules)

# clean rules
seccomp_rules = cleanupSeccompRules(seccomp_rules)

# generate source for seccompInitRoutine
generateSeccompRulesSource(seccomp_rules, seccomp_rules_tracer, "sec_seccomp_rules")

# generate the expression rules
generateEmulatorSource(expression_rules, "sec_syscall_emulator")

print("PROCESS FINISHED: ALL FILES GENERATED")