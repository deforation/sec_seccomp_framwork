###################################################################
# Seccomp Toolkit by Remo Schweizer as a part of the master thesis
#                  ____ _ _  ___  _ _ _ 
#                 |_  /| | || . || | | |
#                  / / |   ||   || | | |
#                 /___||_|_||_|_||__/_/ 
#                      
# The SecInfParser parses the rule file used to generate
# the seccomp and c-based checks
#
# A Rule file has the following base structure
#  - The {action} represents an action like
#    terminate or skip or allow or modify or trap
#
# /////////////////////////////////////////////
#
# [General]
# debug:     				True or False
# default_action:			{action}
# default_action_tracer:	{action}
#
# # defines which systemcalls shoud strictly be allowed, forbidden,...
# syscall {action}:			list of systemcalls like (open, write, ...)
# # the same for the tracer
# tracer {action}:			list of systemcalls like (open, write, ...)
#
# [Global]
# # Allows to define rules targeting all system calls which
# # contain all the given field groups
#
# [{syscall_name}{after}]
# # Allows to specify rules for specific system calls
#
# /////////////////////////////////////////////
#
# There exist different ways to define rules.
# The following constructs are supported:
# Keep in mind, that each rule can only apper once, but it is possible
# to specify multiple checks / actions by separating them with a comma
#
# - {after}			Allows to specify special rules when the system call
#					was already executed, allowing to check and manipulate
#					return parameters of functions like: read, recvmsg, ...
#					The normal behaviour of seccomp is to check the system call
#					before it is executed
#					example: [read:after]
#					exanoke: [recvmsg:after]
#
# - {action} 		represents an action like (terminate, allow or skip)
#
# - {c-expression} 	defines nearly any kind of c expression.
#                  	example: domain == AF_UNIX
#                  	example: domain == AF_UNIX && type == SOCK_STREAM
#				   	example: (rlim->rlim_max < 50 || rlim->rlim_max > 100) && resource == 5
#				   	example: stat->st_uid == getuid()
#
# - {permissions}  	defines a permission string consisting of "rwcx"
#				   	r = read, w = write, c = create, x = execute
#				   	if for example the paremeter flags in the open syscall
# 				   	is added to the group permission_flag, it is checked against
#				   	these flags
#				  	example: allow(r)    path dir_starts_with("/home/remo/read_only_dir")
#				   	example: allow(r)    path not dir_starts_with("/home/remo/read_only_dir")
#
# - {field}		   	defines the field against a value should be checked.
#				   	it can either be the name of the argument or the group name of an argument
#					it is also possible to access elements of a struct as it would be in c
#					example: filename
#					example: buf
#					example: rlim->rlim_max
#
# - {value_check}  	defines a check against a specific value. These can easier be transformed
#				   	into kernel checked system calls.
#				   	example: != AF_IPX
#				   	example: == AF_UNIX or just AF_UNIX
#					example: dir_starts_with("/home/remo/Desktop")
#					example: starts_with("start of a string")
#
# - {new_value}		Defines the new value an argument should get before syscall execution
#					It can either be a value like 10, AF_UNIX, ... or a String "new_string"
#					example: redirect		resource == 1 && rlim->rlim_max > 2048: rlim->rlim_max => 1024
#					example: path redirect:	dir_starts_with("/home/remo/denied") => "/home/remo/allowed"
# 					example: redirect:		filename dir_ends_with(".txt") => ".dat"
#
#
# default:								{action} 	//specifies the default action of a syscall section
#
# {action}:								{c-expression}, {c-expression}, ...
# {action}({permissions}):				{c-expression}, {c-expression}, ...
#
# {field} {action}:						{value_check}, {value_check}, ...
# {field} {action}({permissions}):		{value_check}, {value_check}, ...
#
# redirect:								{c-expression}: {field} => {new_value}, {c-expression}: {field} => {new_value}, ...
# redirect({permissions}):				{c-expression}: {field} => {new_value}, {c-expression}: {field} => {new_value}, ...
# {field} redirect:						{value_check}, {value_check}, ...
# {field} redirect({permissions}):		{value_check}, {value_check}, ...
# 
# /////////////////////////////////////////////
#
# Note: The normal behaviour of seccomp is to check a system call
# before it is executed. Unfortunately, many system calls become
# interesting after they have been executed.
# To be able to inspect the data after the execution,
# the :after flag can be added to the system calls section name.
# With the flag, the rules will be applied once the call is finished.
# - It is possible to define the normal section and the after version
# - Within the c-configuration file, an equivalent function block has to
#   be defined by adding :after to the system call name: SYS_read:after,...
# - The action skip has no effect when the system call was already executed
#
#
# The rule configuration logic allows also 
# to modify and check strings and paths using. 
# The prefix dir_ is necessary if the auto resolve of 
# the path within the system call argument should automatically be resolved
# note that the path parameter is also automatically resolved
# therefore it is possible to define relative paths
#  - dir_starts_with("path") 
#  - dir_contains("path")
#  - dir_ends_with("path")
#
#
# If on the other way, we want to check strings itself, 
# the following functions hould be used:
#  - starts_with("string") 
#  - contains("string")
#  - ends_with("string")
#
#
# There is also a way to perform checks (no modifications) 
# on the path of a file descriptor. Note, that file descriptors 
# generally have no strictly defined path representation, 
# especially if we deal # with hardlinks,... 
# The runctions resolve the path based on the directory "/proc/pid/fd/fdnum
#  - fd_path_starts_with("path") 
#  - fd_path_contains("path")
#  - fd_path_ends_with("path")
#
# -----------------------------------------------------------------
# Version: 1.0
# -----------------------------------------------------------------
# 01.04.2018:       schwerem        Version 1.0 implemented
# -----------------------------------------------------------------
#
# TODO:
#  - Advanced error messages for invalid file formats
#  - More checks to detect file format errors
#
###################################################################

import shlex
from configparser import ConfigParser
from libs.SecRegexBuilder import SecRegexBuilder

class SecInfParser:
	# defines
	SECTION_GENERAL = "General"
	GROUP_EXPRESSION = "Expression"
	GROUP_SETTINGS	 = "settings"

	# basic and standard variables
	debug = False;
	seccomp_default = None
	seccomp_default_tracer = None

	# rules structure
	rules = None;

	# reads the file and does basic parsing
	def read(self, filename):
		config = ConfigParser(strict = True);
		config.read(filename);

		self.__plausibilityCheck(config)
		self.rules = self.__collectRules(config);

	# returns if debug is enabled
	def debugEnabled(self):
		return self.debug;

	# returns the default action for undefined systemcalls
	def getSeccompDefault(self, for_tracer):
		if for_tracer:
			return self.seccomp_default_tracer;
		else:
			return self.seccomp_default;

	# returns the default actions for the customized systemcalls
	def getDefaultActions(self, syscall = None):
		res = [];

		systemcalls = self.getSystemcallsForAction("custom");
		for call in systemcalls:
			if call != "Global":
				for exp in self.rules[call][self.GROUP_EXPRESSION]:
					if exp["action"] == "default":
						if syscall == None:
							res.append({"syscall": call, "action": exp["values"][0]})
						elif syscall == call:
							return exp["values"][0]

		return res;

	# returns all systemcalls for a given action
	def getSystemcallsForAction(self, action, for_tracer = False):
		systemcalls = [];

		if action == "custom":
			for section in self.rules:
				if section != self.SECTION_GENERAL:
					systemcalls.append(section);
		else:
			section = "syscall" if not for_tracer else "tracer";
			if section in self.rules[self.SECTION_GENERAL]:
				for rule in self.rules[self.SECTION_GENERAL][section]:
					if rule["action"] == action:
						for fun in rule["values"]:
							systemcalls.append(fun);

		return systemcalls;

	# return all basic rules based on a specific field
	def getBasicRules(self, section):
		rules = []

		for group, rule in self.rules[section].items():
			if group != self.GROUP_EXPRESSION and group != self.GROUP_SETTINGS:
				for rule_detail in rule:
					rule_detail["field"] = group;
					rules.append(rule_detail);

		return rules;

	# return all basic rules based on a specific field
	def getExpressionRules(self, section):
		rules = [];

		for group, rule in self.rules[section].items():
			if group == self.GROUP_EXPRESSION:
				for r in rule:
					if r["action"] != "default":
						rules.append(r);

		return rules;

	# returns true if a system call exists which supports an after execution check
	def syscallSupportsAfter(self, syscall):
		if ":" in syscall:
			return True;
		else: 
			return syscall + ":after" in self.rules

	# check if it is a syscall only checking the after event
	def syscallIsOnlyAfter(self, syscall):
		syscall = syscall.split(":")[0]
		return not syscall in self.rules;

	# perform some basic plausibility checks on the config file
	def __plausibilityCheck(self, config):
		if not "General" in config.sections():
			print("The General section in the config-file is missing. Abort procedure")
			exit()	

	# collect and parse all rules
	def __collectRules(self, config):
		rules = dict()

		for section in config.sections():
			aftermode = False 
			if ":" in section:
				mode =  section.split(":")[1]
				if  mode != "after":
					print("Section " + section + " is invalid. Only the mode after is availlable")
					exit()
				else:
					aftermode = True

			rules[section] = dict();
			rules[section][self.GROUP_SETTINGS] = dict()
			rules[section][self.GROUP_SETTINGS]["aftermode"] = aftermode;
			for option in config.options(section):
				group = self.GROUP_EXPRESSION;
				action = "";
				rights = "";

				# check if we have an expression (complex structure)
				# or if we have to check only one field
				if " " in option:
					group = option.split(" ")[0]
					action = option.split(" ")[1]
				else:
					action = option;

				if "(" in action:
					reg = SecRegexBuilder();
					reg.scanString("action")
					reg.expectString("\(")
					reg.scanString("rights")
					reg.expectString("\)")
					m = reg.execute(action)

					action = m.group("action");
					rights = m.group("rights");	

				# strip all vaues (separated with ,)
				values = config.get(section, option).replace("\n", "");

				values = values.replace("\"", "-secdQt-")
				values = values.replace("'", "-secsQt-")
				values = values.replace("(", "\"(")
				values = values.replace(")", ")\"")
				values = values.replace("[", "\"[")
				values = values.replace("]", "]\"")
				values = values.replace("{", "\"{")

				splitter = shlex.shlex(values, posix = True);
				splitter.whitespace = ","
				splitter.whitespace_split = True
				values = list(map(lambda x: x.replace("-secdQt-", "\"").replace("-secsQt-", "'").strip(), list(splitter)))

				if group not in rules[section]:
					rules[section][group] = [];

				if section == "General" and action.lower() == "debug":
					self.debug = values[0].lower() in ["true", "yes", "enable", "1"];
				elif section == "General" and action.lower() == "default_action":
					self.seccomp_default = values[0].lower();
				elif section == "General" and action.lower() == "default_action_tracer":
					self.seccomp_default_tracer = values[0].lower();
				else:
					rules[section][group].append({"action": action, "values": values, "rights": rights})	

		if self.seccomp_default is None or self.seccomp_default_tracer is None:
			print("The default seccomp action <default_action> or <default_action_tracer> is not defined in the Section <General>. Abort Process.");
			exit()

		return rules;