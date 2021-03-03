import sys
import os
import re

event_re = re.compile(r"\s*#define\s*REVENT\s*(?P<event>\S*)\s*")
handler_re = re.compile(r"\s*#define\s*RHANDLER\s*(?P<handler>\S*)\s*")


def extract_c_file(c_file):
    meta_info = {}

    f = open(c_file, "r")
    data = f.read()
    f.close()
    meta_info["c_file"] = os.path.basename(c_file)

    captured_event = event_re.search(data)
    if captured_event is None:
        print("generate.py: invalid format of handler plugin [no REVENT defined]")
        exit(-1)
    meta_info["event"] = captured_event.group("event")

    captured_handler = handler_re.search(data)
    if captured_handler is None:
        print("generate.py: invalid format of handler plugin [no RHANDLER defined]")
        exit(-1)
    meta_info["handler"] = captured_handler.group("handler")

    print("generate.py: find %s" % meta_info)
    return meta_info


def extend_buffer(buffer, handlers):
    register_fcns = ""
    for h in handlers:
        buffer += '#include "%s"\n' % h["c_file"]
        buffer += "#undef REVENT\n"
        buffer += "#undef RHANDLER\n"
        register_fcns += "    z_rewriter_register_handler(r, %s, %s);\n" % (
            h["event"],
            h["handler"],
        )

    buffer += (
        """
Z_PRIVATE void __rewriter_init_predefined_handler(Rewriter *r) {
    %s
}
        """
        % register_fcns.strip()
    )

    return buffer


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("generate.py: ./generate.py <directory>")
        exit(-1)

    dir = sys.argv[1].strip()
    in_file = os.path.join(dir, "handler_main.in")
    if not os.path.exists(in_file):
        print("generate.py: %s does not exist" % in_file)
        exit(-1)

    f = open(in_file, "r")
    buffer = f.read() + "\n"
    f.close()

    handlers = []
    for _file in os.listdir(dir):
        if _file.endswith(".c"):
            if "main" in _file:
                continue
            handlers.append(extract_c_file(os.path.join(dir, _file)))

    buffer = extend_buffer(buffer, handlers)

    out_file = os.path.join(dir, "handler_main.c")
    f = open(out_file, "w")
    f.write(buffer)
    f.close()
