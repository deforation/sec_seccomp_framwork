###################################################################
# Seccomp Toolkit by Remo Schweizer as a part of the master thesis
#                  ____ _ _  ___  _ _ _ 
#                 |_  /| | || . || | | |
#                  / / |   ||   || | | |
#                 /___||_|_||_|_||__/_/ 
#                      
# Defines the rule types used by the config builder
# It defines the class SeccompRule which specifies the data fields
# or a rule which is transformed into a seccomp expression
#
# The ExpressionRule defines an object which is transformed 
# into a rule based on c-code
#
# -----------------------------------------------------------------
# Version: 1.0
# -----------------------------------------------------------------
# 01.04.2018:       schwerem        Version 1.0 implemented
# -----------------------------------------------------------------
#
###################################################################

class SeccompRule:
	def __init__(self, syscall, type, action, checks):
		self.syscall = syscall.split(":")[0];
		self.type = type;
		self.action = action;
		self.checks = checks;

	def hasParameterChecks(self):
		return len(self.checks) != 0;

	def getAction(self):
		return self.action;

	def getSyscall(self):
		return self.syscall;

	def getParameterChecks(self):
		return self.checks;

	def __eq__(self, other):
		strings_self = []
		strings_other = []

		for check in self.checks:
			strings_self.append(check["field"] + check["operator"] + check["value"]) 

		for check in other.checks:
			strings_other.append(check["field"] + check["operator"] + check["value"]) 

		strings_self.sort()
		strings_other.sort()

		return "-".join(strings_self) ==  "-".join(strings_other) and self.syscall == other.syscall and self.type == other.type and self.action == other.action;

	def __hash__(self):
		check_hash = 0;
		strings = []
		for check in self.checks:
			strings.append(check["field"] + check["operator"] + check["value"]) 
		strings.sort()

		return hash((self.syscall, self.type, self.action, "-".join(strings)))

	def __repr__(self):
		strings = []
		for check in self.checks:
			strings.append(check["field"] + check["operator"] + check["value"]) 
		strings.sort()

		return "(" + " )( ".join([self.syscall, self.type, self.action, "&&".join(strings)]) + ")"


class ExpressionRule:
	def __init__(self, syscall, type, action, field, check, to, permissions):
		self.syscall = syscall;
		self.type = type;
		self.action = action;
		self.field = field;
		self.check = check;
		self.to = to;
		self.permissions = permissions;

	def getSyscall(self):
		return self.syscall;

	def getAction(self):
		return self.action;

	def getCheck(self):
		return self.check;

	def getField(self):
		return self.field;

	def getNewValue(self):
		return self.to;

	def getPermissions(self):
		return self.permissions;

	def __eq__(self, other):
		return self.syscall == other.syscall and self.type == other.type and self.action == other.action and self.field == other.field and self.check == other.check and self.to == other.to;

	def __hash__(self):
		return hash((self.syscall, self.type, self.action, self.field, self.check, self.to))

	def __repr__(self):
		field = self.field;
		check = self.check;
		if self.field is None:
			field = "";
		if self.check is None:
			check = "";

		if self.to is None:
			return "(" + " )( ".join([self.syscall, self.type, self.action, field, check]) + ")"
		else:
			return "(" + " )( ".join([self.syscall, self.type, self.action, field, check, self.to]) + ")"
