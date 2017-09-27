" This script needs to be run from /Empire directory since it directly uses empire lib"
import os
from lib.common import empire

# FakeMenu class to pass obj to function later
class FakeMenu(object):
    conn = None
    installPath = os.getcwd()

# main = empire.MainMenu(args=args) is a blocking call
# we need a FakeMenu to load modules.
fakeMenu = FakeMenu()
modules = empire.modules.Modules(fakeMenu, [])

# instead of writing py file parsing again, I reuse.
# I organized the modules into a dictionary.
module_classes = {}
for moduleName, module in modules.modules.iteritems():
    if not moduleName.startswith('powershell'):
        continue
    m = moduleName.split('/')
    if m[1] not in module_classes:
        module_classes[m[1]] = {}
    class_name = moduleName.replace(m[0] + '/' + m[1] + '/', "")
    class_name = class_name.replace('/', '_')
    class_name = class_name.replace('-', '_')
    module_classes[m[1]][moduleName] = {'class_name':class_name, 'module_obj': module}

# build the source code from the dictionary formed earlier
source_code = '"""this is auto-generated for EmpireAPIWrapper"""\n\n'
    
for k1, v1 in module_classes.items():
    source_code += "class {0}(object):\n".format(k1)
    for k2, v2 in v1.items():
        source_code += "\tclass {0}(object):\n".format(v2['class_name'])
        description = v2['module_obj'].info['Description']
        source_code += '\t\t"""{0}\n\t\t"""\n\n'.format(description.replace('\\','/'))
        source_code += "\t\tpath = '{0}'\n\n".format(k2)
        source_code += "\t\tclass options(object):"
        for name, option in v2['module_obj'].options.iteritems():
            if option['Required'] is True:
                source_code += "\n\t\t\t{0} = '{1}'".format('required_' + name.lower(), name)
            else:
                if name.isdigit() is True: # 1 special case where option is numeric
                    source_code += "\n\t\t\t{0} = '{1}'".format('_' + name.lower(), name)
                else:
                    source_code += "\n\t\t\t{0} = '{1}'".format(name.lower(), name)
        source_code += "\n\n"

# write the source code to a file
with open("empire.py", "w") as text_file:
    text_file.write(source_code)