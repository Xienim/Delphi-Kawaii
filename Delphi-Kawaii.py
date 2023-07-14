import idaapi
import ida_kernwin


def line_init(line):
    badc = line.replace("<", "_").replace(">", "_").replace(";", "_").replace(",", "_").split()
    if len(badc) >= 2:

        add = line.split()[-1].split("_")[-1]
        
        func_name = badc[1].rsplit("_", 1)[0]
        
        if "sub" in func_name:
            return 0
        try:
            addr = int(add,16)
        except:
            return 0

        idaapi.set_name(addr, func_name)
    else:
        print("EOF.")



def Hi_Kawaii():
    ida_kernwin.info(f"Enter the full path of the MAP file")
    result = ida_kernwin.ask_str("Full PATH to the MAP file", 0, "")
    if result is not None:
        init_get = "Address Publics by Value _ RVA+Base"

        with open(result, "r") as filen:
            start_count = False

            for line in filen:
                line = line.strip()
        
                if line.startswith(init_get):
                    start_count = True
                    continue
        
                if start_count:
                    line_init(line)

class Kawaii_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Delphi-Kawaii :)"
    help = "Any bug or error you find, you should open the request on github."
    wanted_name = "Delphi_Kawaii"
    wanted_hotkey = ""

    def init(self):
        print("Delphi-Kawaii Init")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        Hi_Kawaii()

    def term(self):
        print("Ok!")

def PLUGIN_ENTRY():
    return Kawaii_Plugin()

def PLUGIN_ENTRY_CALLBACK():
    return PLUGIN_ENTRY()

def init_plugin():
    return PLUGIN_ENTRY_CALLBACK()

def run_plugin():
    plugin = PLUGIN_ENTRY()
    plugin.init()

run_plugin()
