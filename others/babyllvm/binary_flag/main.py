#!/usr/bin/python3

from ctypes import CFUNCTYPE, c_long, c_int, POINTER, cast, CDLL, addressof
import sys, os
import llvmlite.ir as llvmIR
import llvmlite.binding as llvm
import traceback
import signal

i8 = llvmIR.IntType(8)
i32 = llvmIR.IntType(32)
i64 = llvmIR.IntType(64)

i8_ptr = llvmIR.PointerType(i8)
i32_ptr = llvmIR.PointerType(i32)
i64_ptr = llvmIR.PointerType(i64)

def findFunctionByName(module, fname):
	for f in module.functions:
		if f._name == fname:
			return f
	return None

def findGlobvarByName(module, gname):
	for g in module.globals:
		if g == gname:
			return module.globals[g]
	return None

def resolveRight(x):

	if type(x) == type((1,2)):
		if x[1] == None:
			return resolveRight(x[0])
		else:
			return resolveRight(x[1])
	else:
		assert(x != None and type(x) != type((1,2)))
		return x

def resolveLeft(x):

	if type(x) == tuple:
		if x[0] == type((1,2)):
			return resolveLeft(x[1])
		else:
			return resolveLeft(x[0])
	else:
		assert(x != None and type(x) != type((1,2)))
		return x

def is_safe(v, wl):
	if wl == None:
		return False
	a1, a2 = wl
	return v >= a1 and v <= a2

def whitelist_add(wl, v):
	assert(not is_safe(v, wl))
	if wl == None:
		return (v, v)
	a1, a2 = wl
	if v < a1:
		return (v, a2)
	elif v > a2:
		return (a1, v)
	else:
		raise Exception("unreachable error")


class bfProgram:
	def __init__ (self, c):
		self.code = c
		self.head = None
		self.br1 = None
		self.br2 = None
		self.isLinear = True

		pars = self.match_par()

		branchpos = self.code.find("[")

		if branchpos != -1:
			assert(branchpos in pars.keys())
			matchpos = pars[branchpos]
			self.head = bfProgram(self.code[:branchpos])
			self.br1 = bfProgram(self.code[branchpos+1:matchpos])
			self.br2 = bfProgram(self.code[matchpos+1:])
			self.isLinear = False

		else:
			i = 0
			state = 0
			imm = 0
			self.shortened_code = []
			L = len(self.code)

			for x in self.code:
				if x == '>':
					if state == 1:
						imm += 1
					else:
						self.shortened_code.append((state, imm))
						state = 1
						imm = 1
				elif x == '<':
					if state == 1:
						imm -= 1
					else:
						self.shortened_code.append((state, imm))
						state = 1
						imm = -1
				elif x == '+':
					if state == 2:
						imm += 1
					else:
						self.shortened_code.append((state, imm))
						state = 2
						imm = 1
				elif x == '-':
					if state == 2:
						imm -= 1
					else:
						self.shortened_code.append((state, imm))
						state = 2
						imm = -1
				elif x == '.':
					if state == 3:
						imm += 1
					else:
						self.shortened_code.append((state, imm))
						state = 3
						imm = 1
				elif x == ',':
					if state == 4:
						imm += 1
					else:
						self.shortened_code.append((state, imm))
						state = 4
						imm = 1

			self.shortened_code.append((state, imm))

	def codegen(self, module, whitelist=None):
		main_routine = findFunctionByName(module, "main_routine")

		if (self.isLinear == True):
			block = main_routine.append_basic_block()
			builder = llvmIR.IRBuilder()
			builder.position_at_end(block)

			dptr_ptr = findGlobvarByName(module, "data_ptr")
			sptr_ptr = findGlobvarByName(module, "start_ptr")
			ptrBoundCheck = findFunctionByName(module, "ptrBoundCheck")
			print_char = findFunctionByName(module, "print_char")
			read_char = findFunctionByName(module, "read_char")
			rel_pos = 0
			if whitelist == None:
				whitelist_cpy = None
			else:
				whitelist_cpy = whitelist[::]

			for op, imm in self.shortened_code:
				if op == 0:
					continue
				elif op == 1:
					if imm != 0:
						ori = builder.ptrtoint(builder.load(dptr_ptr), i64)
						incr = llvmIR.Constant(i64, imm)
						new = builder.inttoptr(builder.add(ori, incr), i8_ptr)
						builder.store(new, dptr_ptr)
						rel_pos += imm
				elif op == 2:
					if imm != 0:
						dptr = builder.load(dptr_ptr)
						if not is_safe(rel_pos, whitelist_cpy):
							sptr = builder.load(sptr_ptr)
							cur = builder.ptrtoint(dptr, i64)
							start = builder.ptrtoint(sptr, i64)
							bound = builder.add(start, llvmIR.Constant(i64, 0x3000))
							builder.call(ptrBoundCheck, [start, bound, cur])
							whitelist_cpy = whitelist_add(whitelist_cpy, rel_pos)
						ori = builder.load(dptr)
						incr = llvmIR.Constant(i8, imm)
						builder.store(builder.add(ori, incr), dptr)
				elif op == 3:
					dptr = builder.load(dptr_ptr)
					if not is_safe(rel_pos, whitelist_cpy):
						sptr = builder.load(sptr_ptr)
						cur = builder.ptrtoint(dptr, i64)
						start = builder.ptrtoint(sptr, i64)
						bound = builder.add(start, llvmIR.Constant(i64, 0x3000))
						builder.call(ptrBoundCheck, [start, bound, cur])
						whitelist_cpy = whitelist_add(whitelist_cpy, rel_pos)
					assert(imm > 0)
					for i in range(imm):
						builder.call(print_char, [builder.load(dptr)])
				elif op == 4:
					dptr = builder.load(dptr_ptr)
					if not is_safe(rel_pos, whitelist_cpy):
						sptr = builder.load(sptr_ptr)
						cur = builder.ptrtoint(dptr, i64)
						start = builder.ptrtoint(sptr, i64)
						bound = builder.add(start, llvmIR.Constant(i64, 0x3000))
						builder.call(ptrBoundCheck, [start, bound, cur])
						whitelist_cpy = whitelist_add(whitelist_cpy, rel_pos)
					assert(imm > 0)
					for i in range(imm - 1):
						builder.call(read_char, [])
					val = builder.call(read_char, [])
					builder.store(val, dptr)
				else:
					raise Exception("unreachable error")

			return (block, None)

		else:
			# create all blocks
			headb = self.head.codegen(module)
			br1b = self.br1.codegen(module, (0, 0))
			br2b = self.br2.codegen(module, (0, 0))

			dptr_ptr = findGlobvarByName(module, "data_ptr")
			sptr_ptr = findGlobvarByName(module, "start_ptr")
			ptrBoundCheck = findFunctionByName(module, "ptrBoundCheck")
			
			# emit code for head
			builder = llvmIR.IRBuilder()
			builder.position_at_end(resolveRight(headb))
			if not is_safe(0, whitelist):
				dptr = builder.load(dptr_ptr)
				sptr = builder.load(sptr_ptr)
				cur = builder.ptrtoint(dptr, i64)
				start = builder.ptrtoint(sptr, i64)
				bound = builder.add(start, llvmIR.Constant(i64, 0x3000))
				builder.call(ptrBoundCheck, [start, bound, cur])
			currentval = builder.load(builder.load(dptr_ptr))
			zero = llvmIR.Constant(i8, 0)
			cond = builder.icmp_unsigned("==", currentval, zero)
			builder.cbranch(cond, resolveLeft(br2b), resolveLeft(br1b))

			# emit code for taken
			builder.position_at_end(resolveRight(br1b))
			if not is_safe(0, whitelist):
				dptr = builder.load(dptr_ptr)
				sptr = builder.load(sptr_ptr)
				cur = builder.ptrtoint(dptr, i64)
				start = builder.ptrtoint(sptr, i64)
				bound = builder.add(start, llvmIR.Constant(i64, 0x3000))
				builder.call(ptrBoundCheck, [start, bound, cur])
			currentval = builder.load(builder.load(dptr_ptr))
			zero = llvmIR.Constant(i8, 0)
			cond = builder.icmp_unsigned("!=", currentval, zero)
			builder.cbranch(cond, resolveLeft(br1b), resolveLeft(br2b))

			return (headb, br2b)

	def match_par (self):
		# validate matching of [ and ]
		charset = "><+-.,"
		stk = []
		rv = dict()

		for i, x in enumerate(self.code):
			if x == '[':
				stk.append((x, i))
			elif x == ']':
				if (len(stk) == 0):
					raise Exception("unmatching parantheses in program")
				ch, idx = stk.pop()
				rv[idx] = i
		
		return rv

def compile(program, verbose=False):

	# initialize module and main_routine
	fty = llvmIR.FunctionType(i32, [i32])
	module = llvmIR.Module()
	main_routine = llvmIR.Function(module, fty, "main_routine")
	
	# add external functions
	fty = llvmIR.FunctionType(i32, [i8])
	print_char = llvmIR.Function(module, fty, "print_char")
	fty = llvmIR.FunctionType(i8, [])
	read_char = llvmIR.Function(module, fty, "read_char")
	fty = llvmIR.FunctionType(i32, [i64, i64, i64])
	ptrBoundCheck = llvmIR.Function(module, fty, "ptrBoundCheck")

	# initialize data_ptr
	data_ptr = llvmIR.GlobalVariable(module, i8_ptr, "data_ptr")
	start_ptr = llvmIR.GlobalVariable(module, i8_ptr, "start_ptr")

	# initialize intro block
	intro = main_routine.append_basic_block()
	builder = llvmIR.IRBuilder()
	builder.position_at_end(intro)
	heap = lruntime.alloc_data()
	builder.store(llvmIR.Constant(i64, heap + 0x10).inttoptr(i8_ptr), data_ptr)
	builder.store(llvmIR.Constant(i64, heap + 0x10).inttoptr(i8_ptr), start_ptr)

	# compile bf code
	body = program.codegen(module)

	# append epilogue
	epilogue = main_routine.append_basic_block()
	builder.position_at_end(epilogue)
	builder.ret(llvmIR.Constant(i32, 1))

	# connect control flow
	builder.position_at_end(intro)
	builder.branch(resolveLeft(body))

	builder.position_at_end(resolveRight(body))
	builder.branch(epilogue)

	# verify generated IR
	strmod = str(module)
	llmod = llvm.parse_assembly(strmod)
	llmod.verify()

	if verbose:
		print(llmod)

	return llmod, heap

def execute(llmod, heap, verbose=False):
	target_machine = llvm.Target.from_default_triple().create_target_machine()

	with llvm.create_mcjit_compiler(llmod, target_machine) as ee:
		ee.add_global_mapping(llmod.get_global_variable("data_ptr")._ptr, heap)
		ee.add_global_mapping(llmod.get_global_variable("start_ptr")._ptr, heap + 0x8)
		ee.finalize_object()
		cfptr = ee.get_function_address("main_routine")
		if verbose:
			print(target_machine.emit_assembly(llmod))
		cfunc = CFUNCTYPE(c_int, c_int)(cfptr)
		if cfunc(1) != 1:
			raise Exception("jitted-code returned an abnormal value")

def banner():
	code = "-[------->+<]>-.-[->+++++<]>++.+++++++..+++.[--->+<]>-----.+[->++<]>+.>-[--->+<]>-.[----->+<]>++.--[-->+++<]>-.+++++++++++++.+.+[-->+++++<]>-.-.++[->++<]>+.-[--->+<]>++.----.+++++.++++++++++.-[---->+<]>++.+[----->+<]>.--[--->+<]>.-[---->+<]>++.+[->++<]>.++++.[-->+<]>---.>-[--->+<]>---.-[->++++<]>+.+++++++++++.----.[->++++<]>--.>++++++++++."
	l, h = compile(bfProgram(code))
	execute(l, h)

def timeout():
	print("timed out!")
	exit(0)

if __name__ == "__main__":

	# cd to where all the good stuff is located
	os.chdir(sys.path[0])

	# alarm
	signal.signal(signal.SIGALRM, timeout)
	signal.alarm(300)

	# initialize llvm backend
	llvm.initialize()
	llvm.initialize_native_target()
	llvm.initialize_native_asmprinter()
	llvm.load_library_permanently("./runtime.so")

	# initialize libruntime
	lruntime = CDLL("./runtime.so")
	lruntime.alloc_data.restype = c_long

	# compile banner printing program
	banner()

	while True:
		code = input(">>> ")
		l, h = compile(bfProgram(code))
		execute(l, h)