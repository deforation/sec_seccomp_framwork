###################################################################
# Seccomp Toolkit by Remo Schweizer as a part of the master thesis
#                  ____ _ _  ___  _ _ _ 
#                 |_  /| | || . || | | |
#                  / / |   ||   || | | |
#                 /___||_|_||_|_||__/_/ 
#                      
# The SecRegexBuilder is a helper tool to build regular expressions
# for the parse operations of the c and inf parser as well as the
# configuration builder 
#
# -----------------------------------------------------------------
# Version: 1.0
# -----------------------------------------------------------------
# 01.04.2018:       schwerem        Version 1.0 implemented
# -----------------------------------------------------------------
#
# TODO:
#  - Change some formulations and parameters for a
#    better understanding
#  - Add documentation to the functions
#
###################################################################

import re

class SecRegexBuilder:
	regex = "";

	def skipRandom(self):
		self.regex += ".*?"

	def findString(self, sym = None, string = None, skip_only_spaces = False):
		if skip_only_spaces:
			if not sym is None:
				self.regex += "[ " + sym + "\t]+"
			elif not string is None:
				self.regex += "[ \t]*" + string + "[ \t]*"
			else:
				self.regex += "[ \t]+"
		else:
			self.skipRandom()
			self.regex += sym;

	def expectString(self, sym):
		self.regex += sym;

	def scanOperator(self, selector, optional = False):
		if optional:
			self.regex += "(?P<" + str(selector) + ">[=\<\>!]+)?"
		else:
			self.regex += "(?P<" + str(selector) + ">[=\<\>!]+)"

	def scanCVariableName(self, selector, quantifier = ""):
		self.regex += "(?P<" + str(selector) + ">[a-zA-Z_][a-zA-Z0-9_\-\>]+)" + quantifier

	def scanCDataType(self, selector):
		self.regex += "(?P<" + str(selector) + ">[a-zA-Z_][a-zA-Z0-9_ ]+)*"

	def scanSecGroupList(self, selector):
		self.regex += "(?P<" + str(selector) + ">([a-zA-Z_+0-9]+,? ?)*)"

	def scanCustom(self, selector, custom, quantifier = ""):
		self.regex += "(?P<" + str(selector) + ">" + custom + ")" + quantifier

	def ignoreSpaces(self):
		self.regex += "[ \t]*"

	def scanValue(self, selector):
		self.regex += "(?P<" + str(selector) + ">[a-zA-Z_.0-9]*)"

	def scanString(self, selector):
		self.regex += "(?P<" + str(selector) + ">[a-zA-Z_.\-\"\/]*)"

	def scanAny(self, selector):
		self.regex += "(?P<" + str(selector) + ">.*)"

	def scanExpression(self, selector):
		self.regex += "(?P<" + str(selector) + ">[a-zA-Z_.\-\>\(\)]*)"

	def scanStringList(self, selector):
		self.regex += "(?P<" + str(selector) + ">([a-zA-Z_.0-9\/]*,? ?)*)"

	def scanParameterList(self, selector):
		self.regex += "(?P<" + str(selector) + ">([a-zA-Z_\-.0-9 *]*,? ?)*)"

	def execute(self, line):
		return re.search(self.regex, line, re.IGNORECASE);

	def build(self):
		return self.regex;
