#查找危险函数，并让其高亮

from idaapi import *

DEBUG=True

#set all dangerous_functions and backdoor function
dangerous_functions=[
    "strcpy",
    "strcat",
    "sprintf",
    "read",
    "getenv"
]

attention_functions=[
    "memcpy",
    "strncpy",
    "sscanf",
    "strncat",
    "snprintf",
    "vprintf",
    "printf"
]

command_execution_function=[
    "system",
    "execve",
    "popen",
    "unlink"
]

#describe arg num of function

one_arg_function=[
    "getenv",
    "system",
    "unlink"
]

two_arg_function=[
    "strcpy",
    "strcat",
    "popen"
]

three_arg_function = [
    "strncpy",
    "strncat", 
    "memcpy",
    "execve",
    "read"
]

format_function_offset_dict = {
    "sprintf":1,
    "sscanf":1,
    "snprintf":2,
    "vprintf":0,
    "printf":0
}

def getFuncAddr(func_name):
    addr=LocByName(func_name)
    if addr!=BADADDR:
        return addr
    return False

def getArgAddr(func_addr,argNum):
    args=[]
    for i in idaapi.get_arg_addrs(func_addr):
        idc.set_cmt(i,"addr: 0x%x" % (func_addr),0)#设置注释
        idc.set_color(i,CIC_ITEM,0x00ff00)
        args.append(i)
    
def getArg