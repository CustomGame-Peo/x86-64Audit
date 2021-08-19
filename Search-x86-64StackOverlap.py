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

command_execution_functions=[
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

#查找参数地址，并添加注释
def getArgAddr(func_addr,argNum):
    args=[]
    for i in idaapi.get_arg_addrs(func_addr):
        idc.set_cmt(i,"addr: 0x%x" % (func_addr),0)#设置注释
        idc.set_color(i,CIC_ITEM,0x00ff00)
        args.append(i)
    return args
    
#
def getArgs(addr):
    x86mov=['mov','lea']
    #如果是参数不是寄存器传值(寄存器传值的返回值为1)
    if get_operand_type(addr,1) !=1:
        arg=idc.print_operand(addr,1)
        set_cmt()
        
def audit(func_name):
    func_addr=getFuncAddr(func_name)
    while 
        
def main_Audit():
    print('Auditing dangerous functions ......')
    for i in dangerous_functions:
        audit(i)
    print('Auditing attention function ......')
    for i in attention_functions:
        audit(i)
    print('Auditing attention function ......')
    for i in command_execution_functions:
        audit(i)