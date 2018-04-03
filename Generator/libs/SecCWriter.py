###################################################################
# Seccomp Toolkit by Remo Schweizer as a part of the master thesis
#                  ____ _ _  ___  _ _ _ 
#                 |_  /| | || . || | | |
#                  / / |   ||   || | | |
#                 /___||_|_||_|_||__/_/ 
#                      
# The SecCWriter component of the seccomp toolkit 
# formates c based source code and writes it into a file
#
# -----------------------------------------------------------------
# Version: 1.0
# -----------------------------------------------------------------
# 01.04.2018:		schwerem		Version 1.0 implemented
# -----------------------------------------------------------------
#
# TODO:
#  - consider that curly brackets can occure in strings. those
#    should not be taken into account for the indent calculation
#
###################################################################

class SecCWriter:
	# exports code into a file
	# filename: specifies the filename
	# loc: is a list of strings representing the source code
	def exportCode(self, filename, loc):
		bracket_count = 0;

		inDefaultCase = False;
		default_bracket_count = 0;

		src = ""
		space_before_func_begin = False;
		for line in loc:
			#if "{" in line:
			#	src = "{:s}".format(src);

			# bracket calculation
			bracket_count -= line.count("}")
			if inDefaultCase and default_bracket_count == bracket_count:
				inDefaultCase = False;
				bracket_count -= 1;

			# add source line
			src = "{:s}{:s}{:s}\n".format(src, "\t" * bracket_count, line.strip());
			bracket_count += line.count("{")

			# indent handling for switch cases
			if "case" in line:
				bracket_count += 1;
			if "break;" in line:
				bracket_count -= 1;
				src = "{:s}\n".format(src);	
			if "default:" in line:
				inDefaultCase = True;
				default_bracket_count = bracket_count;
				bracket_count += 1;

			if bracket_count == 0:
				if not space_before_func_begin:
					src = "{:s}\n".format(src);	
					space_before_func_begin = True;
			else:
				space_before_func_begin = False;

		f = open(filename, "w");
		f.write(src);
		f.close()
