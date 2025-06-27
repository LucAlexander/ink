import json

def load(filename):
    with open(f'{filename}.json', 'r') as infile:
        data = json.load(infile)
    return data

def write(filename, content):
    with open(f'{filename}.ink', 'w') as outfile:
        outfile.write('external {\n')
        outfile.write('\timport global "SDL2/SDL.h"\n')
        [outfile.write(f'\t{item}\n') for item in content if item != '']
        outfile.write('}\n')

def process(data):

    def convert_unit_type(type_map):
        match type_map["tag"]:
            case ":pointer":
                return f"({convert_unit_type(type_map['type'])})^"
            case ":array":
                return f"({convert_unit_type(type_map['type'])})^"
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
                for field in type_map['fields']:
                    lval = convert_unit_type(field['type'])
                    if lval == '':
                        return ''
                    definition += f"{lval} {field['name']};"
                definition += "}"
                return definition
            case "union":
                definition = "union {"
                for field in type_map['fields']:
                    lval = convert_unit_type(field['type'])
                    if lval == '':
                        return ''
                    definition += f"{lval} {field['name']};"
                definition += "}"
                return definition
            case "enum":
                definition = "enum {"
                for i, num in enumerate(type_map['fields']):
                    if i != 0:
                        defintion += ", "
                    definition += f"{num['name']}={num['value']}"
                definition += "}"
                return definition
            case ":struct":
                return ''
            case ":union":
                return ''
            case ":enum":
                return ''
            case other:
                if other[0] == ':':
                    return "UNHANDLED"
                if other[0] == '<':
                    return ''
                return other

    def convert_function(item):
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
        return f"{arg_type}{return_type} {item['name']};"

    def convert_type(item):
        rval = convert_unit_type(item['type'])
        if rval == '':
            return ''
        return f"type {item['name']} = {rval};"
            
    convert = {
        'function': convert_function,
        'typedef' : convert_type
    }

    return [
       convert[item["tag"]](item)
       for item in data
       if item["tag"] in convert
    ]

if __name__=='__main__':
    write('sdl2', process(load('sdl2')))
