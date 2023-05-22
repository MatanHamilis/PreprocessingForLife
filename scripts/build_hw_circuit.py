input_size = 128
output_size = 64
gates = []


def make_xor(input_a, input_b, output):
    return ([input_a, input_b], [output], "XOR")


def make_and(input_a, input_b, output):
    return ([input_a, input_b], [output], "AND")


def make_not(input, output):
    return ([input], [output], "INV")


def emit_gate(gate):
    inputs = ' '.join(str(i) for i in gate[0])
    input_count = len(gate[0])
    outputs = ' '.join(str(i) for i in gate[1])
    output_count = len(gate[1])
    op = gate[2]
    return "{} {} {} {} {}".format(input_count, output_count, inputs, outputs, op)


current_output = input_size


def get_fresh_wire():
    global current_output
    output = current_output
    current_output += 1
    return output


def make_header(gates):
    global current_output
    first_line = "{} {}".format(len(gates), current_output)
    second_line = "1 {}".format(input_size)
    last_line = "1 {}".format(output_size)
    return '\n'.join([first_line, second_line, last_line, ""])


if __name__ == "__main__":
    for i in range(0, input_size//2):
        gates.append(make_xor(i, input_size - i-1, get_fresh_wire()))
    print(make_header(gates))
    for g in gates:
        print(emit_gate(g))
