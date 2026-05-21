import json
import sys

def load(filename):
    with open(f'{filename}.json', 'r') as infile:
        data = json.load(infile)
    return data

def write(filename, content):
    with open(f'{filename}.ink', 'w') as outfile:
        outfile.write('external {\n')
        [outfile.write(f'\t{item}\n') for item in content if item != '']
        outfile.write('}\n')

enum_count = 0

def process(data):

    def convert_unit_type(type_map):
        global enum_count
        match type_map["tag"]:
            case ":pointer":
                lval = convert_unit_type(type_map['type'])
                if lval == '':
                    return ''
                return f"({lval})^"
            case ":array":
                lval = convert_unit_type(type_map['type'])
                if lval == '':
                    return ''
                return f"({lval})^"
            case ":void":
                return "u8"
            case ":char":
                return "i8"
            case ":signed-char":
                return "i8"
            case ":unsigned-char":
                return "u8"
            case ":short":
                return "i16"
            case ":unsigned-short":
                return "u16"
            case ":signed-short":
                return "i16"
            case ":int":
                return "i32"
            case ":unsigned-int":
                return "u32"
            case ":signed-int":
                return "i32"
            case ":long":
                return "i64"
            case ":signed-long":
                return "i64"
            case ":signed-long-long":
                return "i64"
            case ":long-long":
                return "i64"
            case ":unsigned-long":
                return "u64"
            case ":unsigned-long-long":
                return "u64"
            case ":__bf16":
                return "f32"
            case ":float":
                return "f32"
            case ":double":
                return "f64"
            case ":long-double":
                return "f64"
            case ":function-pointer":
                return "[u8]"
            case "struct":
                definition = "struct {"
                if len(type_map['fields']) == 0:
                    definition += "u8^ empty;"
                for field in type_map['fields']:
                    lval = convert_unit_type(field['type'])
                    if lval == '':
                        return ''
                    definition += f"{lval} {field['name']};"
                definition += "}"
                return definition
            case "union":
                definition = "union {"
                if len(type_map['fields']) == 0:
                    definition += "u8^ empty;"
                for field in type_map['fields']:
                    lval = convert_unit_type(field['type'])
                    if lval == '':
                        return ''
                    definition += f"{lval} {field['name']};"
                definition += "}"
                return definition
            case "enum":
                definition = "enum {"
                if len(type_map['fields']) == 0:
                    defintion += f"INK_EMPTY_EXTERN{enum_count}"
                    enum_count += 1
                for i, num in enumerate(type_map['fields']):
                    if i != 0:
                        definition += ", "
                    definition += f"{num['name']}={num['value']}"
                definition += "}"
                return definition
            case ":struct":
                return type_map['name']
            case ":union":
                return type_map['name']
            case ":enum":
                return type_map['name']
            case '__builtin_va_list':
                return 'u8^'
            case other:
                if other[0] == ':':
                    return "UNHANDLED"
                if other[0] == '<':
                    return ''
                return other

    functions = {}
    types = {}

    def convert_function(item):
        if item['name'] in functions:
            return ''
        if item["variadic"] == True or item["storage-class"] == "static":
            return ''
        args = item["parameters"]
        return_type = convert_unit_type(item["return-type"])
        if return_type == '':
            return ''
        arg_type = ''
        for arg in args:
            converted_arg = convert_unit_type(arg["type"])
            if (converted_arg == ''):
                return ''
            arg_type = f"{arg_type}{converted_arg} -> "
        functions[item['name']] = True
        return f"{arg_type}{return_type} {item['name']};"

    def convert_typedef(item):
        rval = convert_unit_type(item['type'])
        if rval == '':
            return ''
        match item['type']['tag']:
            case "struct":
                return f"alias {item['name']} = {rval};"
            case ":struct":
                return f"alias {item['name']} = {rval};"
            case "union":
                return f"alias {item['name']} = {rval};"
            case ":union":
                return f"alias {item['name']} = {rval};"
            case "enum":
                return f"alias {item['name']} = {rval};"
            case ":enum":
                return f"alais{item['name']} = {rval};"
        return f"alias {item['name']} = {rval};"
            
    def convert_struct_type(item):
        if item['name'] in types:
            return ''
        rval = convert_unit_type(item)
        if rval == '':
            return ''
        types[item['name']] = True
        match item['tag']:
            case 'struct':
                return f"type {item['name']} = {rval};"
            case 'enum':
                return f"type {item['name']} = {rval};"
            case 'union':
                return f"type {item['name']} = {rval};"
        return ''

    convert = {
        'function': convert_function,
        'typedef' : convert_typedef,
        'struct' : convert_struct_type,
        'enum' : convert_struct_type,
        'union' : convert_struct_type
    }

    return [
       convert[item["tag"]](item)
       for item in data
       if item["tag"] in convert
    ]

if __name__=='__main__':
    assert len(sys.argv) == 2, "provide json ffi stub name\n"
    stub = sys.argv[1]
    write(stub, process(load(stub)))
