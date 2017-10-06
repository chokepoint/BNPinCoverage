from binaryninja import *

def reset_highlight(view):
    blockcount = 0.0
    for func in view.functions:
        for bb in func.basic_blocks:
            bb.highlight = HighlightStandardColor.NoHighlightColor
            blockcount += 1
    view.session_data['blockcount'] = blockcount

def import_pin_trace(view):
    reset_highlight(view)

    e_types = ['ET_NONE', 'ET_REL', 'ET_EXEC', 'ET_DYN', 'ET_CORE']
    addrs = []
    offset = 0
            
    filename = get_open_filename_input("Import Pin Trace", "*.ptrace")

    # If this is a PIE executable, grab the ELF entry point for calculating the slide
    if view.view_type == 'ELF':
        try:
            elf_type = e_types[ord(view.read(0x10, 1))]
            if elf_type == 'ET_DYN':
                start_loc = view.entry_point
        except TypeError:
            elf_type = 'ET_EXEC'
            
    with open(filename) as fd:
        first_line = True
        for line in fd:
            if line.startswith("BB:"):
                addr = int(line.split(' ', 1)[1], 16)
                if first_line and elf_type == 'ET_DYN':
                    offset = addr - start_loc
                    first_line = False
                addrs.append(addr - offset)

    addrs.sort()
    uaddrs = set(addrs)

    for addr in uaddrs:
        try:
            bb = view.get_basic_blocks_at(addr)[0]
            bb.highlight = highlight.HighlightStandardColor.CyanHighlightColor
        except Exception:
            pass
    blockcount = view.session_data['blockcount']
    show_message_box("Coverage", "Basic blocks hit (%d / %d) = %.2f" % (len(uaddrs), blockcount, (len(uaddrs) / blockcount * 100)))

PluginCommand.register("Clear Pin Highlighting", "Remove highlighting from every basic block", reset_highlight)
PluginCommand.register("Import Pin Trace", "Import a Pin Trace", import_pin_trace)
