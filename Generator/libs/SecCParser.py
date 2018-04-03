###################################################################
# Seccomp Toolkit by Remo Schweizer as a part of the master thesis
#                  ____ _ _  ___  _ _ _ 
#                 |_  /| | || . || | | |
#                  / / |   ||   || | | |
#                 /___||_|_||_|_||__/_/ 
#                      
# The CParser parses the c system call configuration file
# It provides functions to retrieve data about arguments 
# and code sections
#
# This module prepares basically data structures which are 
# easy to use within the configuration builder
#
# Therefore it interpretes also the custom comment modifies
# for a system call wrapper
#
# For all functions, the field parameter can either be the 
# argument name of a system call or one of its group specifiers
# which was defined using: set_group[{field_name}]: {group_name}
#
# -----------------------------------------------------------------
# Version: 1.0
# -----------------------------------------------------------------
# 01.04.2018:		schwerem		Version 1.0 implemented
# -----------------------------------------------------------------
#
# TODO:
#  - More checks to detect an invalid configuartion file
#  - More useful error messages
#
###################################################################

from enum import Enum
from libs.SecRegexBuilder import SecRegexBuilder

# defines the code section types
class Section(Enum):
	includes 	 = 1
	macros 		 = 2
	secfunctions = 3
	groups 		 = 4

# defines the parse section types
class ParseSection(Enum):
	none 		= 1
	comment 	= 2
	source 		= 3

# will be thrown, if arguments are defined which are not
# part of the system call
class FieldNotFoundError(Exception):
    def __init__(self, message, errors = None):
        super().__init__(message)
        self.errors = errors

class CParser:
	sections = None

	# reads the given c file
	def read(self, filename):
		self.file = open(filename, "r").readlines();

		self.sections = self.__loadSections()
		self.sections[Section.secfunctions] = self.__parseSecFunctions(self.sections[Section.secfunctions])
		self.sections[Section.groups] = self.__collectParameterGroups(self.sections[Section.secfunctions])

	# returns if the field is primitive (not a pointer)
	def isFieldPrimitive(self, syscall, field):
		el = self.__getArgumentData(syscall, field);
		return not el["pointer"]

	# returns the number of the argument (Needed for modifications and seccomp rules)
	def getArgumentNr(self, syscall, field):
		el = self.__getArgumentData(syscall, field);
		return el["argument_nr"]		

	# returns all information about an argument
	# if field_as_argument_nr is set, the field parameter is treated
	# as the argument number
	def getArgumentInfo(self, syscall, field, field_as_argument_nr = False):
		return self.__getArgumentData(syscall, field, field_as_argument_nr);

	# returns all wrapper function definitions
	def getSystemCallWrapperFunctions(self):
		return self.sections[Section.secfunctions];

	# returns the list of includes for a system call
	def getSyscallHeaders(self, syscall):
		syscall = syscall if "SYS_" in syscall else "SYS_" + syscall

		funcinfo = self.__findElement(self.sections[Section.secfunctions], "systemcall", syscall)
		if funcinfo:
			if "headers" in funcinfo:
				return funcinfo["headers"]
			else:
				return []
		else:
			return []

	# returns a dictionary of all groups specifiers and their argument name
	def getGroupFieldLink(self, syscall):
		syscall = syscall if "SYS_" in syscall else "SYS_" + syscall
		return list(filter(lambda r: r["syscall"]  == syscall, self.sections[Section.groups]))		

	# returns systemcall argument which corresponds to the group "permission_flag"
	def getPermissionFlag(self, syscall):
		try:
			el = self.__getArgumentData(syscall, "permission_flag");
			return el["name"]
		except FieldNotFoundError as e:
			return None;

	# Generates the function prototype of the system call
	def generatePrototype(self, funcinfo, addpid = False):
		bracket = "{" if funcinfo["bracket_on_prototype"] else ""
		proto = "void {:s}(_ARGS_){:s}".format(funcinfo["function"], bracket)

		arguments = []
		if addpid:
			arguments.append("pid_t pid")

		for i in range(0, 6):
			for name, arginfo in funcinfo["arguments"].items():
				if int(arginfo["argument_nr"]) == i:
					arguments.append(self.__buildArgumentString(name, arginfo))
		
		proto = proto.replace("_ARGS_", ", ".join(arguments))

		return proto;

	# Builds the argument string with const, datatype pointer and variable name
	def __buildArgumentString(self, name, arginfo):
		const = "const" if arginfo["const"] else ""
		ptr = "*" if arginfo["pointer"] else ""
		datatype = arginfo["datatype"];

		return "{:s} {:s} {:s}{:s}".format(const, datatype, ptr, name).strip()

	# Finds and returns the argument data of a syscall accordint to the field specifier
	# The field can either be the argument name or the group name of the argument
	# if field_as_argument_nr is true, the field parameter is the number of the argument
	def __getArgumentData(self, syscall, field, field_as_argument_nr = False):
		# handle field if it is a complex object (element of a pointer)
		if field_as_argument_nr == False:
			if "->" in field:
				field = field.split("->")[0]

		el = self.__findElement(self.sections[Section.secfunctions], "systemcall", "SYS_" + syscall)
		if el == None:
			el = self.__findElement(self.sections[Section.secfunctions], "systemcall", syscall)

		if el != None:
			if field_as_argument_nr:
				for key, arg in el["arguments"].items():
					if arg["argument_nr"] == field:
						return arg;
			else:
				if field in el["arguments"]:
					return el["arguments"][field];
				else:
					for key, arg in el["arguments"].items():
						if "group" in arg:
							if field in arg["group"]:
								return arg;

			raise FieldNotFoundError("Could not find a source specification for the field or group name <{:s}> of the systemcall <{:s}>. Abort Process".format(str(field), syscall))
		else:
			raise FieldNotFoundError("Could not find a source specification for the field <{:s}>. Abort Process".format(str(field)));


	# finds an element within a list of dictionaries
	# where a specific field matches a specific value
	def __findElement(self, data, key, value):
		for el in data:
			if key in el:
				if el[key] == value:
					return el;
		return None;

	# checks if the line represents a section start
	# param: code line
	# return: None or Section name
	def __checkAndGetSectionStart(seslf, line):
		reg = SecRegexBuilder();
		reg.findString("//")
		reg.findString("section-start:")
		reg.ignoreSpaces()
		reg.scanString("section");
		m = reg.execute(line)

		if m != None:
			return m.group("section").lower().strip()
		else:
			return None;

	# checks if the line specifies a section end
	# return true if it is an end marker, otherwise false
	def __isSectionEnd(self, line):
		return "section-end" in line.lower();

	# reads the soruce and splits it into their sections
	# return: Dictionary of the content groups with an array for all code lines
	def __loadSections(self):
		sections = {"includes": Section.includes, "macros": Section.macros, "secfunctions": Section.secfunctions}
		content = {Section.includes: {"raw": []}, Section.macros: {"raw": []}, Section.secfunctions: {"raw": []}}

		in_section = False;
		current_section = None;

		counter = 0;
		for line in self.file:
			counter += 1;

			# check for section end
			if self.__isSectionEnd(line):
				in_section = False;
				current_section = None;

			# add source line to section
			if in_section:
				content[current_section]["raw"].append(line.strip())

			# check for section start
			section = self.__checkAndGetSectionStart(line)
			if section:
				# check if we are already in a section
				if in_section:
					print("Section '{:s}' was never closed. Abort Process.".format(current_section.name))
					exit()				

				# specify current section
				in_section = True;
				try:
					current_section = sections[section]
				except Exception as  e:
					print("Section '{:s}' on line {:d} is not a valid section specifier".format(section, counter))
					exit()

		if in_section:
			print("Section '{:s}' was never closed. Abort Process.".format(current_section.name))
			exit()

		return content;

	# checks if the line starts a comment section
	def __isCommentBeginn(self, line):
		return "/*" in line;

	def __isFunctionBeginn(self, line):
		return "void" in line;
	
	# checks if the line ends a comment section
	def __isCommentEnd(self, line):
		return "*/" in line;

	def __iterNext(selc, iter):
		try:
			return next(iter);
		except StopIteration:
			return None;

	# strips a string element or an array of strings
	def __stripData(self, data):
		new_data = None
		if isinstance(data, list):
			new_data = []
			for old in data:
				new_data.append(old.strip())
		elif isinstance(data, dict):
			new_data = data;
		elif isinstance(data, bool):
			new_data = data;
		elif isinstance(data, int):
			new_data = data;
		else:
			new_data = data.strip()

		return new_data;

	# adds a dictionary to a dictionary with a child value on a child
	def __setChildChildKeyValue(self, dictionary, key, childkey, childchildkey, value):
		if not key.strip() in dictionary:
			dictionary[key.strip()] = dict()

		if not childkey.strip() in dictionary[key.strip()]:
			dictionary[key.strip()][childkey.strip()] = dict();

		dictionary[key.strip()][childkey.strip()][childchildkey.strip()] = self.__stripData(value);

	# adds a dictionary to a dictionary with a child value
	def __setChildKeyValue(self, dictionary, key, childkey, value):
		if not key.strip() in dictionary:
			dictionary[key.strip()] = dict()

		dictionary[key.strip()][childkey.strip()] = self.__stripData(value);

	# adds a value to a dictionary
	def __setKeyValue(self, dictionary, key, value):
		if not key.strip() in dictionary:
			dictionary[key.strip()] = dict()	

		dictionary[key.strip()] = self.__stripData(value);

	# parses a specific option for a sec function definition
	def __parseSecFunctionComment_option(self, option, line, data, scan_list = False):
		reg = SecRegexBuilder();
		reg.findString(option)
		reg.findString(":")
		reg.ignoreSpaces()
		if scan_list == True:
			reg.scanStringList("value");
		else:
			reg.scanString("value");
		m = reg.execute(line)

		if "value" in m.groupdict():
			self.__setKeyValue(data, option, m.group("value") if scan_list == False else m.group("value").split(","))
		else:
			print("Syntax error in line <{:s}>. Invalid Option value".format(line));
			exit()	

	# parses the set_group property of a comment
	def __parseSecFunctionComment_parameter_option(self, option, line, data, single_item = False):
		reg = SecRegexBuilder();
		reg.findString(option + "\[")
		reg.scanCVariableName("variable")
		reg.findString("\]")
		reg.findString(":")
		reg.ignoreSpaces()
		reg.scanSecGroupList("groups");
		m = reg.execute(line)

		if "variable" in m.groupdict() and "groups" in m.groupdict():
			if single_item == False:
				self.__setChildChildKeyValue(data, "arguments", m.group("variable"), option[4:], m.group("groups").split(","))
			else:
				self.__setChildChildKeyValue(data, "arguments", m.group("variable"), option[4:], m.group("groups").split(",")[0])
		else:
			print("Syntax error in line <{:s}>. Invalid variable name or group definition".format(line));
			exit()	

	# parses all relevant lines of a comment section
	def __parseSecFunctionComment(self, line, line_iter, data):
		syscall_defined = False;

		while not self.__isCommentEnd(line):
			line_lower = line.lower();

			if "set_group" in line_lower:
				self.__parseSecFunctionComment_parameter_option("set_group", line_lower, data);
			elif "set_length" in line_lower:
				self.__parseSecFunctionComment_parameter_option("set_length", line_lower, data, single_item = True);
			elif "systemcall" in line_lower:
				self.__parseSecFunctionComment_option("systemcall", line, data);
				syscall_defined = True;
			elif "headers" in line_lower:
				self.__parseSecFunctionComment_option("headers", line, data, scan_list = True);

			line = self.__iterNext(line_iter);

		if not syscall_defined:
			print("There is a function with a missing link to a systemcall.\nMake sure the option systemcall: value is set in the comment section.")
			exit()

		return data;

	# parses a single function parameter (datatype + variable name)
	def __parseSecFunctionSource_parameter(self, line, data, argument_nr):
		reg = SecRegexBuilder();
		reg.skipRandom()
		reg.scanCustom("isout", "__OUT ", quantifier = "?")
		reg.scanCustom("isconst", "const ", quantifier = "?")
		reg.scanCDataType("datatype")
		reg.scanCustom("isptr", "[ \*]+")
		reg.scanCVariableName("variable")
		m = reg.execute(line)


		if "isout" in m.groupdict() and "datatype" in m.groupdict() and "isptr" in m.groupdict() and "variable" in m.groupdict():
			is_out = False if m.group("isout") == None else True;
			is_const = False if m.group("isconst") == None else True;
			datatype = m.group("datatype").strip()
			is_ptr = True if "*" in m.group("isptr") else False;
			variable = m.group("variable").strip()

			self.__setChildChildKeyValue(data, "arguments", variable, "pointer", is_ptr)
			self.__setChildChildKeyValue(data, "arguments", variable, "const", is_const)
			self.__setChildChildKeyValue(data, "arguments", variable, "out", is_out)
			self.__setChildChildKeyValue(data, "arguments", variable, "datatype", datatype)
			self.__setChildChildKeyValue(data, "arguments", variable, "argument_nr", argument_nr)
			self.__setChildChildKeyValue(data, "arguments", variable, "name", variable)
		else:
			print("Syntax error in Parameter <{:s}>. Please check if the declaration is in a correct c syntax.".format(line));
			exit()	

	# parses the parameter types for the system call functions
	def __parseSecFunctionSource_prototype(self, line, data):
		reg = SecRegexBuilder();
		reg.findString("void")
		reg.ignoreSpaces()
		reg.scanCVariableName("function_name")
		reg.findString("\(")
		reg.scanParameterList("parameters")
		reg.findString("\)")
		reg.ignoreSpaces()
		reg.scanCustom("bracket", "{?", quantifier = "?")
		m = reg.execute(line)

		if "function_name" in m.groupdict() and "parameters" in m.groupdict():
			#m.group("function_name")
			params = self.__stripData(m.group("parameters").split(","))
			argument_nr = 1;
			for param in params:
				self.__parseSecFunctionSource_parameter(param, data, argument_nr);
				argument_nr += 1

			self.__setKeyValue(data, "function", m.group("function_name"));
			self.__setKeyValue(data, "bracket_on_prototype", m.group("bracket") == "{");
		else:
			print("Syntax error in line <{:s}>. Function declaration is invalid.".format(line));
			exit()	

	# parses the source code
	def __parseSecFunctionSource(self, line, line_iter, data):
		void_defined = False;
		first_bracket_found = False;

		bracket_count = 0;
		source = [];
		while (bracket_count > 0 or first_bracket_found == False) and line != None:
			# check for custom macros macros
			if void_defined == True:
				source.append(line)

			# parse specific source lines
			if "void" in line and void_defined == False:
				self.__parseSecFunctionSource_prototype(line, data);
				void_defined = True;

			# count brackets to determine the function end
			bracket_count += line.count("{") - line.count("}");
			first_bracket_found = True if bracket_count > 0 else first_bracket_found;

			if (bracket_count > 0 or first_bracket_found == False):
				line = self.__iterNext(line_iter);

		self.__setKeyValue(data, "raw", source);

		if not void_defined:
			print("There is one function which has not the return value void.\nMake sure all functions have the return value void");
			exit()

		return data;

	# parses all functions
	def __parseSecFunctions(self, data):
		parse_section = ParseSection.none;

		line_iter = iter(data["raw"]);
		line = self.__iterNext(line_iter);

		functions = [];
		data = dict()
		while line != None:
			if self.__isCommentBeginn(line):
				if parse_section == ParseSection.none:
					self.__parseSecFunctionComment(line, line_iter, data);
					parse_section = ParseSection.comment;
				else:
					print("There were multiple function comment blocks after the {:s} specificaition block found. Abort process.".format(data["systemcall"]))
					exit()

			if self.__isFunctionBeginn(line):
				if parse_section == ParseSection.comment:
					self.__parseSecFunctionSource(line, line_iter, data);
					parse_section = ParseSection.source;
				else:
					print("There was a function after the function {:s} detected without a specification comment block. Abort Process.".format(functions[-1]["function"]))
					exit()

			if parse_section == ParseSection.source:
				parse_section = ParseSection.none;
				functions.append(data);
				data = dict()

			line = self.__iterNext(line_iter);

		return functions;

	# collects all parameter groups and returns a list
	# of dictionaries containing the systemcall name, the group and the associated field name
	def __collectParameterGroups(self, funcdefs):
		groups = []

		for func in funcdefs:
			for arg, argdata in func["arguments"].items():
				if "group" in argdata:
					for g in argdata["group"]:
						if g not in groups:
							groups.append({"syscall": func["systemcall"], "group": g, "field": argdata["name"]})

		return groups;
