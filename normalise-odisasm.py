#!/usr/bin/python3
import sys, re

def add_zeroes(inst): #keeps instruction lengths 8 digits long after mathsing with them
	return "0" * (8 - len(inst)) + inst

def print_inst(line): 
	if len(line) > 2:
		print(line[0] + "   " + line[1] + "   " + line[2] + (13 - len(line[2])) * " " + " ".join(line[3:]))
	else: 
		print(line[0] + "   " + line[1])

def main(argv): 
	assert(argv[0])
	file = open(argv[0], 'r')
	lines = file.readlines()
	for line in lines: 
		words = line.split()

		if re.match("[0-9a-f]{8}", words[0]): #we have an instruction
			if len(words[1]) == 8: #if 32 bit instruction
				nextline = [add_zeroes(hex(int(words[0], 16) + 1)[2:]), words[1][:4]]
				words[1] = (words[1][4:])
				print_inst(words)
				print_inst(nextline)
			else: 
				print_inst(words)


if __name__ == "__main__":
    main(sys.argv[1:])

#normalise_odisasm.py <inputfile> > <outputfile>