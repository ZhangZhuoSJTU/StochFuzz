import csv
import os
import sys

template = """
Z_PRIVATE void __libfunc_load(GHashTable *d) {
%s
}
"""

filename = "library_functions_load.c"


def generate_from_csv(filename):
    code = ""
    n = 0

    with open(filename, "r") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        for row in csv_reader:
            if len(row) != 4:
                print("invalid input: %s" % line)
                exit(-1)

            demangled_name = row[0].strip()  # useless currently

            name = row[1].strip()
            if len(name) == 0:
                print("empty library function name")
                exit(-1)

            lcfg = row[2].strip().upper()
            if len(lcfg) == 0:
                lcfg = "UNK"

            lra = row[3].strip().upper()
            if len(lra) == 0:
                lra = "UNK"

            code += """
    LFuncInfo *lf_%d = __lfunc_info_create("%s", LCFG_%s, LRA_%s);
    g_hash_table_insert(d, (gpointer)z_strdup("%s"), (gpointer)lf_%d);
            """ % (
                n,
                name,
                lcfg,
                lra,
                name,
                n,
            )
            n += 1

    return code


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("generate.py: ./generate.py <library_functions.csv> <directory>")
        exit(-1)

    dirname = sys.argv[2].strip()
    csv_filename = os.path.join(dirname, sys.argv[1].strip())
    out_filename = os.path.join(dirname, filename)

    code = generate_from_csv(csv_filename)

    f = open(out_filename, "w")
    f.write(template % code)
    f.close()
